//! The derived analysis must reach the conclusion the measurements support,
//! and must refuse to reach one they do not.

use keyhog_profile::{
    BottleneckKindV2, CacheId, CausalProfileV2, RunIdentity, RunInsightV2, RunState, Session,
    SerialScopeV2, Stage,
};
use std::sync::{Arc, Barrier};

fn identity(threads: usize) -> RunIdentity {
    let mut identity = RunIdentity::new("0.5.68", "detectors", "config", "filesystem", "text", "auto");
    identity.scanner_threads = threads;
    identity.logical_cpus = 8;
    identity
}

/// Drain the families the CLI drains, in the CLI's order, so a test cannot
/// pass against an ordering the product does not use.
fn finish(session: Session, state: RunState) -> CausalProfileV2 {
    let runtime = session.runtime();
    let stage_concurrency = runtime.take_session_stage_concurrency();
    let worker_occupancy = runtime.take_session_worker_occupancy();
    let queue_depths = runtime.take_session_queue_depths();
    let blocked_waits = runtime.take_session_blocked_waits();
    let caches = runtime.take_session_cache_effectiveness();
    let indexed_counters = runtime.take_session_indexed_counters();
    let mut causal = CausalProfileV2::from_v1(session.finish(state));
    causal.stage_concurrency = stage_concurrency;
    causal.worker_occupancy = Some(worker_occupancy);
    causal.queue_depths = queue_depths;
    causal.blocked_waits = blocked_waits;
    causal.caches = caches;
    causal.indexed_counters = indexed_counters;
    causal
}

fn spin(nanoseconds: u64) {
    let start = std::time::Instant::now();
    while start.elapsed().as_nanos() < u128::from(nanoseconds) {
        std::hint::spin_loop();
    }
}

/// A region that one thread holds while every other thread waits is the
/// barrier the profiler exists to name. Sixteen threads then run in parallel
/// for the same duration, so a profiler that only summed stage time would
/// report the two as equal cost.
#[test]
fn a_single_threaded_barrier_is_reported_as_serial_and_the_parallel_region_is_not() {
    let session = Session::start(identity(16)).expect("start session");
    let runtime = session.runtime();
    {
        let _barrier = keyhog_profile::serial_span(Stage::SourceWalk);
        spin(20_000_000);
    }
    let gate = Arc::new(Barrier::new(16));
    let workers: Vec<_> = (0..16)
        .map(|_| {
            let runtime = runtime.clone();
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || {
                runtime.scope(|| {
                    gate.wait();
                    let _work = keyhog_profile::span(Stage::ConfirmedPatterns);
                    spin(20_000_000);
                })
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("join worker");
    }
    let profile = finish(session, RunState::Completed);
    let insight = RunInsightV2::derive(&profile);

    let walk = insight
        .serial_regions
        .iter()
        .find(|region| region.subject == "source-walk")
        .expect("the declared barrier must be reported");
    assert_eq!(walk.scope, SerialScopeV2::Stage);
    assert!(walk.declared, "serial_span must mark the region declared");
    assert_eq!(walk.worker_count, 1, "one thread held the barrier");

    assert!(
        !insight
            .serial_regions
            .iter()
            .any(|region| region.subject == "confirmed-patterns"),
        "a region sixteen workers ran concurrently is not a serial barrier: {:?}",
        insight.serial_regions
    );

    let confirmed = insight
        .stages
        .iter()
        .find(|stage| stage.metric_id.as_str() == "confirmed-patterns")
        .expect("the parallel region must be attributed");
    // The box this runs on may be loaded, so sixteen workers will not read as
    // sixteen. What must hold is that it reads well above the serial
    // threshold, which is what keeps it out of the barrier list.
    assert!(
        confirmed.concurrency_milli > 1_500,
        "sixteen concurrent workers must read above the serial threshold, got {}",
        confirmed.concurrency_milli
    );
    assert_eq!(confirmed.worker_count, 16);
}

/// An inclusive wrapper spans the whole run but its children do the work.
/// Naming it serial would send an operator after the wrong region.
#[test]
fn an_inclusive_wrapper_around_parallel_children_is_not_called_serial() {
    let session = Session::start(identity(8)).expect("start session");
    let runtime = session.runtime();
    let outer = keyhog_profile::span(Stage::BackendDispatch);
    let gate = Arc::new(Barrier::new(8));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let runtime = runtime.clone();
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || {
                runtime.scope(|| {
                    gate.wait();
                    let _work = keyhog_profile::span(Stage::Entropy);
                    spin(30_000_000);
                })
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("join worker");
    }
    drop(outer);
    let profile = finish(session, RunState::Completed);
    let insight = RunInsightV2::derive(&profile);

    assert!(
        !insight
            .serial_regions
            .iter()
            .any(|region| region.subject == "backend-dispatch"),
        "backend-dispatch wraps the parallel work; it is not a barrier: {:?}",
        insight.serial_regions
    );
}

/// Hits and misses must survive the shard merge and produce the rate an
/// operator reads, because a cache nobody can measure is a cache nobody fixes.
#[test]
fn cache_hit_rate_merges_across_workers() {
    let session = Session::start(identity(4)).expect("start session");
    let runtime = session.runtime();
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let runtime = runtime.clone();
            std::thread::spawn(move || {
                runtime.scope(|| {
                    for _ in 0..3 {
                        keyhog_profile::record_cache_hit(CacheId::AutorouteDecision);
                    }
                    keyhog_profile::record_cache_miss(CacheId::AutorouteDecision);
                })
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("join worker");
    }
    let profile = finish(session, RunState::Completed);

    let cache = profile
        .caches
        .iter()
        .find(|cache| cache.cache == CacheId::AutorouteDecision)
        .expect("a consulted cache must be reported");
    assert_eq!(cache.hits, 12);
    assert_eq!(cache.misses, 4);
    assert_eq!(cache.hit_rate_ppm, 750_000);

    let insight = RunInsightV2::derive(&profile);
    assert!(
        insight
            .findings
            .iter()
            .all(|finding| finding.kind != BottleneckKindV2::CacheMiss),
        "a 75 percent hit rate is not a cache-miss finding"
    );
}

/// A cache that misses most of the time is the finding, not a footnote. This
/// is the shape of the autoroute decision cache that cannot hit at all.
#[test]
fn a_cache_that_never_hits_becomes_a_named_finding() {
    let session = Session::start(identity(1)).expect("start session");
    for _ in 0..40 {
        keyhog_profile::record_cache_miss(CacheId::AutorouteDecision);
    }
    let profile = finish(session, RunState::Completed);
    let insight = RunInsightV2::derive(&profile);

    let finding = insight
        .findings
        .iter()
        .find(|finding| finding.kind == BottleneckKindV2::CacheMiss)
        .expect("a cache with zero hits over forty lookups must be named");
    assert_eq!(finding.subject, "autoroute-decision");
    assert!(
        finding.statement.contains("0.0%"),
        "the statement must carry the rate: {}",
        finding.statement
    );
}

/// Nesting must not charge a worker twice, or occupancy would exceed the wall
/// clock and every idle number derived from it would be wrong.
#[test]
fn nested_spans_do_not_double_count_worker_occupancy() {
    let session = Session::start(identity(1)).expect("start session");
    {
        let _outer = keyhog_profile::span(Stage::BackendDispatch);
        for _ in 0..4 {
            let _inner = keyhog_profile::span(Stage::Entropy);
            spin(2_000_000);
        }
    }
    let profile = finish(session, RunState::Completed);
    let occupancy = profile
        .worker_occupancy
        .as_ref()
        .expect("occupancy must be recorded");

    assert_eq!(
        occupancy.calls, 1,
        "only the outermost span contributes occupancy"
    );
    let summed: u64 = profile
        .stages
        .iter()
        .map(|stage| stage.elapsed_ns)
        .sum::<u64>();
    assert!(
        occupancy.busy_ns < summed,
        "busy {} must be below the summed inclusive total {summed}",
        occupancy.busy_ns
    );
}

/// An out-of-range slot must be counted, never folded into a neighbour, or one
/// decoder's cost would be reported as another's.
#[test]
fn an_out_of_range_indexed_slot_is_counted_rather_than_misattributed() {
    let session = Session::start(identity(1)).expect("start session");
    keyhog_profile::add_indexed_counter(keyhog_profile::IndexedCounterId::DecoderElapsedNs, 3, 500);
    keyhog_profile::add_indexed_counter(
        keyhog_profile::IndexedCounterId::DecoderElapsedNs,
        u16::try_from(keyhog_profile::INDEXED_COUNTER_SLOTS).expect("slot count fits"),
        900,
    );
    let profile = finish(session, RunState::Completed);

    let record = profile
        .indexed_counters
        .iter()
        .find(|record| record.counter == keyhog_profile::IndexedCounterId::DecoderElapsedNs)
        .expect("a written family must be reported");
    assert_eq!(record.slots.len(), keyhog_profile::INDEXED_COUNTER_SLOTS);
    assert_eq!(record.slots[3], 500);
    assert_eq!(
        record.slots.iter().sum::<u64>(),
        500,
        "the out-of-range write must not land in any slot"
    );
    assert_eq!(record.dropped_out_of_range, 1);
}

/// Benchmarks call reset between rounds to discard warm-up. Anything left
/// behind is reported as the next round's measurement.
#[test]
fn reset_clears_every_shard_held_family() {
    let session = Session::start(identity(1)).expect("start session");
    {
        let _span = keyhog_profile::span(Stage::Entropy);
        spin(1_000_000);
    }
    keyhog_profile::record_cache_hit(CacheId::MatcherArtifact);
    keyhog_profile::add_indexed_counter(keyhog_profile::IndexedCounterId::DecoderElapsedNs, 2, 77);
    keyhog_profile::add_counter(keyhog_profile::CounterId::DecodeExtractCalls, 5);
    keyhog_profile::add_input_bytes(4_096);

    keyhog_profile::reset();

    let profile = finish(session, RunState::Completed);
    assert!(profile.caches.is_empty(), "cache counts survived reset");
    assert!(
        profile.indexed_counters.is_empty(),
        "indexed counters survived reset"
    );
    assert!(
        profile.stage_concurrency.is_empty(),
        "stage concurrency survived reset"
    );
    assert_eq!(
        profile.identity.workload.raw_source_bytes, 0,
        "input bytes survived reset"
    );
    assert!(
        profile
            .typed_metrics
            .iter()
            .all(|metric| metric.value == 0 || metric.metric_id.as_str() == "process-cpu-time"),
        "a typed counter survived reset: {:?}",
        profile.typed_metrics
    );
    let occupancy = profile.worker_occupancy.expect("occupancy is recorded");
    assert_eq!(occupancy.busy_ns, 0, "worker occupancy survived reset");
}

/// The summary is useless if the reader has to find the conclusion. The first
/// line is the conclusion.
#[test]
fn the_summary_leads_with_the_bottleneck() {
    let session = Session::start(identity(1)).expect("start session");
    {
        let _barrier = keyhog_profile::serial_span(Stage::SourceWalk);
        spin(30_000_000);
    }
    let profile = finish(session, RunState::Completed);
    let insight = RunInsightV2::derive(&profile);
    let summary = insight.render_summary();
    let first = summary.lines().next().expect("summary is never empty");

    assert!(
        first.starts_with("bottleneck "),
        "first line must state the conclusion, got {first:?}"
    );
    assert!(
        first.contains(insight.bottleneck().kind.as_str()),
        "first line must name the kind, got {first:?}"
    );
}

/// Two runs are compared by diffing their records, so every derived value must
/// be an integer. A float would make an unchanged run look changed.
#[test]
fn every_derived_value_serializes_as_an_integer() {
    let session = Session::start(identity(2)).expect("start session");
    {
        let _span = keyhog_profile::span(Stage::Entropy);
        spin(1_000_000);
    }
    keyhog_profile::add_input_bytes(8_192);
    keyhog_profile::add_input_units(4);
    let profile = finish(session, RunState::Completed);
    let insight = RunInsightV2::derive(&profile);
    let json = serde_json::to_value(&insight).expect("insight serializes");

    fn assert_no_floats(value: &serde_json::Value, path: &str) {
        match value {
            serde_json::Value::Number(number) => assert!(
                !number.is_f64(),
                "{path} is a float ({number}); derived values must be integers"
            ),
            serde_json::Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    assert_no_floats(item, &format!("{path}[{index}]"));
                }
            }
            serde_json::Value::Object(fields) => {
                for (key, item) in fields {
                    assert_no_floats(item, &format!("{path}.{key}"));
                }
            }
            _ => {}
        }
    }
    assert_no_floats(&json, "insight");
}
