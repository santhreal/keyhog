//! Blocked wait time separated from runnable execution.

use keyhog_profile::{
    blocked, set_attribution, span, Attribution, Evidence, MetricId, RunIdentity, RunState,
    Session, Stage,
};

fn session(name: &str) -> Session {
    Session::start(RunIdentity::new(
        "0.5.49",
        "detectors",
        "config",
        name,
        "test",
        "cpu-simd",
    ))
    .expect("start profile")
}

/// A blocked wait must accumulate into a dedicated per-stage record whose
/// nanoseconds exactly equal the stage's measured elapsed time when every
/// call is blocked, so runnable time is simply elapsed minus blocked.
#[test]
fn blocked_wait_matches_stage_elapsed_exactly() {
    let session = session("blocked-equals-elapsed");
    let runtime = session.runtime();
    for _ in 0..10 {
        drop(blocked(Stage::SourceQueueWait));
    }
    drop(span(Stage::SourceRead));

    let waits = runtime.take_session_blocked_waits();
    assert_eq!(waits.len(), 1);
    assert_eq!(waits[0].version, 1);
    assert_eq!(waits[0].metric_id, MetricId::SourceQueueWait);
    assert_eq!(waits[0].calls, 10);
    assert!(waits[0].blocked_ns > 0);

    let profile = session.finish(RunState::Completed);
    let wait_stage = profile
        .stages
        .iter()
        .find(|measurement| measurement.stage == Stage::SourceQueueWait)
        .expect("wait stage measurement");
    assert_eq!(wait_stage.calls, 10);
    assert_eq!(wait_stage.elapsed_ns, waits[0].blocked_ns);
    let runnable_ns = wait_stage.elapsed_ns - waits[0].blocked_ns;
    assert_eq!(runnable_ns, 0);
    let read_stage = profile
        .stages
        .iter()
        .find(|measurement| measurement.stage == Stage::SourceRead)
        .expect("read stage measurement");
    assert_eq!(read_stage.calls, 1);
}

/// Blocked wait must never be counted as attributed (decoded) execution even
/// while decode attribution is active, keeping wait time out of productive
/// work totals.
#[test]
fn blocked_wait_is_never_attributed_execution() {
    let session = session("blocked-not-attributed");
    let runtime = session.runtime();
    set_attribution(Attribution::Decoded);
    drop(blocked(Stage::ScannerQueueWait));
    drop(span(Stage::Decode));
    set_attribution(Attribution::Root);

    let waits = runtime.take_session_blocked_waits();
    assert_eq!(waits.len(), 1);
    assert_eq!(waits[0].metric_id, MetricId::ScannerQueueWait);

    let profile = session.finish(RunState::Completed);
    let wait_stage = profile
        .stages
        .iter()
        .find(|measurement| measurement.stage == Stage::ScannerQueueWait)
        .expect("wait stage measurement");
    assert_eq!(wait_stage.attributed_ns, 0);
    let decode_stage = profile
        .stages
        .iter()
        .find(|measurement| measurement.stage == Stage::Decode)
        .expect("decode stage measurement");
    assert_eq!(decode_stage.attributed_ns, decode_stage.elapsed_ns);
    assert!(decode_stage.elapsed_ns > 0);
}

/// Blocked waits from concurrent workers must merge exactly across shards.
#[test]
fn blocked_waits_merge_across_concurrent_workers() {
    let session = session("blocked-concurrent");
    let runtime = session.runtime();
    let workers: Vec<_> = (0..3)
        .map(|_| {
            let runtime = runtime.clone();
            std::thread::spawn(move || {
                runtime.scope(|| {
                    for _ in 0..10 {
                        drop(blocked(Stage::SourceQueueWait));
                    }
                    drop(blocked(Stage::ScannerQueueWait));
                });
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("worker completes");
    }

    let waits = runtime.take_session_blocked_waits();
    assert_eq!(waits.len(), 2);
    assert_eq!(waits[0].metric_id, MetricId::SourceQueueWait);
    assert_eq!(waits[0].calls, 30);
    assert_eq!(waits[1].metric_id, MetricId::ScannerQueueWait);
    assert_eq!(waits[1].calls, 3);
    assert!(waits.iter().all(|wait| wait.blocked_ns > 0));
    let _ = session.finish(RunState::Completed);
}

/// Blocked intervals nested inside a running stage must stay causal children
/// while still being accounted as wait, so execution time excludes them on
/// the blocked record but not on the span tree.
#[test]
fn blocked_interval_nested_in_execution_keeps_causal_link() {
    let session = session("blocked-nested");
    let runtime = session.runtime();
    let outer = span(Stage::BackendDispatch);
    drop(blocked(Stage::SourceQueueWait));
    drop(outer);

    let waits = runtime.take_session_blocked_waits();
    assert_eq!(waits.len(), 1);
    assert_eq!(waits[0].calls, 1);

    let (spans, dropped) = runtime.take_session_span_records();
    assert_eq!(dropped, 0);
    assert_eq!(spans.len(), 2);
    let parent = spans
        .iter()
        .find(|record| record.metric_id == MetricId::BackendDispatch)
        .expect("execution span");
    let wait = spans
        .iter()
        .find(|record| record.metric_id == MetricId::SourceQueueWait)
        .expect("wait span");
    assert_eq!(
        wait.parent_span_id,
        Evidence::recorded(parent.span_id),
        "wait stays a causal child of the executing stage"
    );
    assert_eq!(wait.inclusive_ns, waits[0].blocked_ns);
    let _ = session.finish(RunState::Completed);
}

/// The blocked API outside any runtime must remain a safe no-op guard.
#[test]
fn blocked_without_runtime_is_noop() {
    let guard = blocked(Stage::SourceQueueWait);
    assert!(!guard.is_recording());
    drop(guard);
}
