use keyhog_profile::{
    add_input_bytes, add_input_units, reset, set_attribution, set_enabled, span,
    take_stage_measurements, Attribution, CacheState, DaemonState, RunIdentity, RunProfile,
    RunState, Session, Stage, PROFILE_SCHEMA,
};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

static PROFILE_TEST_LOCK: Mutex<()> = Mutex::new(());

fn isolated_profile_test() -> MutexGuard<'static, ()> {
    let guard = PROFILE_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    set_enabled(false);
    reset();
    set_attribution(Attribution::Root);
    guard
}

fn identity(label: &str) -> RunIdentity {
    RunIdentity::new(
        "0.5.49",
        "detectors-a",
        "config-a",
        label,
        "small-text",
        "auto",
    )
}

/// A disabled span must remain the one-load fast path and must not leak stale measurements.
#[test]
fn disabled_span_records_no_stage_or_input_totals() {
    let _guard = isolated_profile_test();

    let guard = span(Stage::Preprocess);
    assert!(!guard.is_recording());
    drop(guard);
    add_input_bytes(41);
    add_input_units(3);

    assert_eq!(take_stage_measurements(), Vec::new());
}

/// The legacy scanner dump may drain its counters mid-run without erasing the session record.
#[test]
fn legacy_counter_drain_preserves_active_session_measurements() {
    let _guard = isolated_profile_test();
    let session = Session::start(identity("filesystem")).expect("start profile session");

    {
        let measured = span(Stage::Phase1Triggers);
        assert!(measured.is_recording());
        std::thread::sleep(Duration::from_millis(1));
    }
    let legacy = take_stage_measurements();
    assert_eq!(legacy.len(), 1);
    assert_eq!(legacy[0].stage, Stage::Phase1Triggers);
    assert_eq!(legacy[0].calls, 1);

    let profile = session.finish(RunState::Completed);
    assert_eq!(profile.stages.len(), 1);
    assert_eq!(profile.stages[0].stage, Stage::Phase1Triggers);
    assert_eq!(profile.stages[0].calls, 1);
    assert!(profile.stages[0].elapsed_ns >= 1_000_000);
}

/// A complete profile must preserve run identity, causal states, decoded attribution, and exact input totals through JSON.
#[test]
fn session_round_trip_preserves_causal_profile_record() {
    let _guard = isolated_profile_test();
    let mut run_identity = identity("filesystem+git-history");
    run_identity.backend_selected = Some("cpu-ac".to_owned());
    run_identity.cache_state = CacheState::Warm;
    run_identity.daemon_state = DaemonState::Client;
    run_identity.scanner_threads = 8;
    run_identity.reader_threads = Some(3);
    let mut session = Session::start(run_identity.clone()).expect("start profile session");

    session.transition(RunState::Acquiring);
    add_input_bytes(65_537);
    add_input_units(7);
    session.transition(RunState::Scanning);
    session.transition(RunState::Resolving);
    set_attribution(Attribution::Decoded);
    {
        let _span = span(Stage::Decode);
        std::thread::sleep(Duration::from_millis(1));
    }
    set_attribution(Attribution::Root);
    session.transition(RunState::Verifying);
    session.transition(RunState::Reporting);
    let profile = session.finish(RunState::Completed);

    assert_eq!(profile.schema, PROFILE_SCHEMA);
    assert_eq!(profile.identity, run_identity);
    assert_eq!(profile.status, RunState::Completed);
    assert_eq!(profile.input_bytes, 65_537);
    assert_eq!(profile.input_units, 7);
    assert_eq!(profile.stages.len(), 1);
    assert_eq!(profile.stages[0].stage, Stage::Decode);
    assert_eq!(profile.stages[0].calls, 1);
    assert_eq!(
        profile.stages[0].attributed_ns,
        profile.stages[0].elapsed_ns
    );
    assert!(profile.wall_time_ns >= profile.stages[0].elapsed_ns);
    assert_eq!(
        profile
            .transitions
            .iter()
            .map(|transition| transition.state)
            .collect::<Vec<_>>(),
        vec![
            RunState::Created,
            RunState::Acquiring,
            RunState::Scanning,
            RunState::Resolving,
            RunState::Verifying,
            RunState::Reporting,
            RunState::Completed,
        ]
    );
    assert_eq!(profile.resource_samples.len(), profile.transitions.len());
    assert_eq!(
        profile
            .states
            .iter()
            .map(|state| state.state)
            .collect::<Vec<_>>(),
        vec![
            RunState::Created,
            RunState::Acquiring,
            RunState::Scanning,
            RunState::Resolving,
            RunState::Verifying,
            RunState::Reporting,
        ]
    );
    assert!(
        profile
            .states
            .iter()
            .map(|state| state.elapsed_ns)
            .sum::<u64>()
            <= profile.wall_time_ns
    );
    assert!(profile.states.iter().all(|state| state
        .resident_start_bytes
        .zip(state.resident_end_bytes)
        .is_some_and(|(start, finish)| start > 0 && finish > 0)));
    assert!(profile.resource_samples.iter().all(|sample| sample
        .snapshot
        .resident_bytes
        .is_some_and(|bytes| bytes > 0)));
    assert!(profile
        .resources
        .max_observed_resident_bytes
        .is_some_and(|bytes| bytes > 0));

    let json = profile.to_json_pretty().expect("serialize profile");
    let decoded: RunProfile = serde_json::from_str(&json).expect("deserialize profile");
    assert_eq!(decoded, profile);
    let mut legacy_json: serde_json::Value =
        serde_json::from_str(&json).expect("parse profile JSON value");
    legacy_json
        .as_object_mut()
        .expect("profile JSON object")
        .remove("states");
    let legacy: RunProfile =
        serde_json::from_value(legacy_json).expect("deserialize additive legacy record");
    assert!(legacy.states.is_empty());
}

/// Concurrent process-global sessions must fail explicitly, and dropping the owner must release the slot.
#[test]
fn concurrent_session_is_rejected_and_drop_releases_slot() {
    let _guard = isolated_profile_test();
    let first = Session::start(identity("first")).expect("start first profile session");
    let error = Session::start(identity("second"))
        .err()
        .expect("reject concurrent session");
    assert_eq!(
        error.to_string(),
        "a KeyHog profile session is already active in this process"
    );
    drop(first);

    let replacement = Session::start(identity("replacement")).expect("session slot released");
    assert_eq!(
        replacement.finish(RunState::Failed).status,
        RunState::Failed
    );
}

/// Linux resource snapshots must observe real process CPU time and thread transitions without a system-wide refresh.
#[cfg(target_os = "linux")]
#[test]
fn linux_resource_snapshots_track_cpu_and_thread_changes() {
    let _guard = isolated_profile_test();
    let mut session = Session::start(identity("linux-process-resources"))
        .expect("start Linux resource profile session");
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        ready_tx.send(()).expect("publish worker readiness");
        done_rx.recv().expect("wait for worker completion");
    });
    ready_rx.recv().expect("observe live worker");
    session.transition(RunState::Acquiring);

    let started = Instant::now();
    let mut accumulator = 0x9e37_79b9_u64;
    while started.elapsed() < Duration::from_millis(75) {
        accumulator = accumulator
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        std::hint::black_box(accumulator);
    }
    done_tx.send(()).expect("release worker");
    worker.join().expect("join worker");
    session.transition(RunState::Scanning);
    let profile = session.finish(RunState::Completed);

    let acquiring = profile
        .states
        .iter()
        .find(|measurement| measurement.state == RunState::Acquiring)
        .expect("acquiring state measurement");
    assert!(
        acquiring
            .cpu_time_ms
            .is_some_and(|milliseconds| milliseconds >= 40),
        "75 ms of busy work must produce a material process CPU delta: {acquiring:?}"
    );
    assert!(
        acquiring
            .aggregate_cpu_milli_percent
            .is_some_and(|milli_percent| milli_percent >= 40_000),
        "CPU utilization must agree with the measured busy interval: {acquiring:?}"
    );
    assert!(
        acquiring
            .threads_start
            .zip(acquiring.threads_end)
            .is_some_and(|(start, finish)| start > finish),
        "the boundary snapshots must observe the live worker and its exit: {acquiring:?}"
    );
}

/// The text export must name exact causal inputs and measurements without serializing source content.
#[test]
fn text_report_exposes_actionable_identity_and_resource_fields() {
    let _guard = isolated_profile_test();
    let mut run_identity = identity("stdin");
    run_identity.backend_selected = Some("scalar".to_owned());
    let session = Session::start(run_identity).expect("start profile session");
    {
        let _span = span(Stage::Reporting);
        std::thread::sleep(Duration::from_millis(1));
    }
    let report = session.finish(RunState::Completed).render_text();

    assert!(report
        .lines()
        .next()
        .is_some_and(|line| line.starts_with("KeyHog profile ")));
    assert!(report.contains(
        "state=completed source=stdin workload=small-text backend_requested=auto \
         backend_selected=scalar cache=unknown daemon=off"
    ));
    assert!(report.contains("version=0.5.49 detector_digest=detectors-a config_digest=config-a"));
    assert!(report.contains(
        "input_bytes=0 input_units=0 throughput_mib_s=0.000 scanner_threads=0 reader_threads=auto logical_cpus="
    ));
    assert!(report.contains("reporting"));
    assert!(report.contains("macro created"));
    assert!(report.contains("per_call_us="));
    assert!(report.contains("bottleneck macro=created"));
    assert!(report.contains("summed_stage=reporting"));
    assert!(report.contains("calls=1 per_call_us="));
    assert!(report.contains("attributed_ms=0.000"));
    assert!(report.contains("resources aggregate_cpu="));
    assert!(report.contains("max_observed_rss_bytes="));
}
