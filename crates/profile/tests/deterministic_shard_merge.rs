//! Deterministic shard merging at session finish.

use keyhog_profile::{add_counter, add_input_units, span, CounterId, MetricId, Runtime, Stage};
use std::sync::{Arc, Barrier};
use std::time::Duration;

/// Merged snapshot of every order-sensitive output that must be identical
/// across runs over the same work regardless of thread scheduling.
#[derive(Debug, Eq, PartialEq)]
struct MergedSnapshot {
    stage_calls: Vec<(Stage, u64)>,
    typed_metrics: Vec<(MetricId, u64)>,
    latency_call_counts: Vec<(MetricId, u64)>,
    worker_count: u64,
    total_calls: u64,
    max_share_ppm: u64,
    median_share_ppm: u64,
    idle_share_ppm: u64,
    sorted_worker_calls: Vec<u64>,
}

fn run_work(stagger: bool) -> MergedSnapshot {
    let runtime = Runtime::new();
    let barrier = Arc::new(Barrier::new(4));
    let workers: Vec<_> = (0..4_u64)
        .map(|index| {
            let runtime = runtime.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                if stagger {
                    // Reverse the registration order with staggered starts.
                    std::thread::sleep(Duration::from_millis((3 - index) * 5));
                } else {
                    barrier.wait();
                }
                runtime.scope(|| {
                    for _ in 0..(index + 1) * 100 {
                        drop(span(Stage::BackendDispatch));
                    }
                    add_counter(CounterId::InputUnits, index + 1);
                    add_input_units(1);
                });
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("worker completes");
    }

    let latency_call_counts: Vec<(MetricId, u64)> = runtime
        .take_session_latency_distributions()
        .iter()
        .map(|distribution| (distribution.metric_id, distribution.call_count))
        .collect();
    let typed_metrics: Vec<(MetricId, u64)> = runtime
        .take_session_typed_metrics()
        .iter()
        .map(|metric| (metric.metric_id, metric.value))
        .collect();
    let imbalance = runtime.take_session_worker_imbalance();
    let mut sorted_worker_calls: Vec<u64> = imbalance
        .workers
        .iter()
        .map(|worker| worker.calls)
        .collect();
    sorted_worker_calls.sort_unstable();
    let stage_calls = vec![(Stage::BackendDispatch, imbalance.total_calls)];
    MergedSnapshot {
        stage_calls,
        typed_metrics,
        latency_call_counts,
        worker_count: imbalance.worker_count,
        total_calls: imbalance.total_calls,
        max_share_ppm: imbalance.max_share_ppm,
        median_share_ppm: imbalance.median_share_ppm,
        idle_share_ppm: imbalance.idle_share_ppm,
        sorted_worker_calls,
    }
}

/// Two runs over identical work with different thread scheduling must produce
/// identical merged counters, latency call counts, and imbalance shares.
#[test]
fn different_thread_scheduling_produces_identical_merged_outputs() {
    let simultaneous = run_work(false);
    let staggered = run_work(true);
    assert_eq!(simultaneous, staggered);
    assert_eq!(simultaneous.total_calls, 1_000);
    assert_eq!(simultaneous.worker_count, 4);
    assert_eq!(simultaneous.typed_metrics, vec![(MetricId::InputUnits, 14)]);
    assert_eq!(
        simultaneous.latency_call_counts,
        vec![(MetricId::BackendDispatch, 1_000)]
    );
    assert_eq!(simultaneous.sorted_worker_calls, vec![100, 200, 300, 400]);
}

/// Worker records must come out in ascending shard-sequence order so repeated
/// drains of the same run are byte-identical regardless of lock acquisition
/// order at registration.
#[test]
fn worker_records_are_sorted_by_stable_shard_sequence() {
    let runtime = Runtime::new();
    let barrier = Arc::new(Barrier::new(3));
    let workers: Vec<_> = (0..3_u64)
        .map(|index| {
            let runtime = runtime.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                runtime.scope(|| {
                    for _ in 0..(index + 1) * 10 {
                        drop(span(Stage::SourceRead));
                    }
                });
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("worker completes");
    }

    let imbalance = runtime.take_session_worker_imbalance();
    assert_eq!(imbalance.workers.len(), 3);
    let worker_ids: Vec<u64> = imbalance
        .workers
        .iter()
        .map(|worker| worker.worker_id)
        .collect();
    assert_eq!(worker_ids, vec![1, 2, 3]);
    let mut calls: Vec<u64> = imbalance
        .workers
        .iter()
        .map(|worker| worker.calls)
        .collect();
    calls.sort_unstable();
    assert_eq!(calls, vec![10, 20, 30]);
}
