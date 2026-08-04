//! Per-worker load and work-stealing imbalance metrics from sharded counters.

use keyhog_profile::{span, Runtime, Stage};

/// Imbalance from known uneven loads must report exact worker count, call
/// totals, busiest and median shares, and idle share in parts per million.
#[test]
fn uneven_shards_produce_exact_imbalance_metrics() {
    let runtime = Runtime::new();
    let workers: Vec<_> = [400_u32, 200, 100, 0]
        .into_iter()
        .map(|calls| {
            let runtime = runtime.clone();
            std::thread::spawn(move || {
                runtime.scope(|| {
                    for _ in 0..calls {
                        drop(span(Stage::BackendDispatch));
                    }
                });
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("worker completes");
    }

    let imbalance = runtime.take_session_worker_imbalance();
    assert_eq!(imbalance.version, 1);
    assert_eq!(imbalance.worker_count, 4);
    assert_eq!(imbalance.total_calls, 700);
    assert!(imbalance.total_elapsed_ns > 0);
    // 400/700, 200/700, and 1/4 in parts per million (truncated division).
    assert_eq!(imbalance.max_share_ppm, 571_428);
    assert_eq!(imbalance.median_share_ppm, 285_714);
    assert_eq!(imbalance.idle_share_ppm, 250_000);
    assert_eq!(imbalance.workers.len(), 4);
    assert!(imbalance
        .workers
        .windows(2)
        .all(|pair| pair[0].worker_id < pair[1].worker_id));
    let mut calls: Vec<u64> = imbalance.workers.iter().map(|worker| worker.calls).collect();
    calls.sort_unstable();
    assert_eq!(calls, vec![0, 100, 200, 400]);
    for worker in &imbalance.workers {
        assert_eq!(worker.version, 1);
        assert_eq!(
            worker.elapsed_ns > 0,
            worker.calls > 0,
            "elapsed time appears exactly on workers that executed calls"
        );
    }
}

/// A perfectly balanced run must report equal shares and zero idle workers.
#[test]
fn balanced_shards_report_equal_shares_and_no_idle() {
    let runtime = Runtime::new();
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let runtime = runtime.clone();
            std::thread::spawn(move || {
                runtime.scope(|| {
                    for _ in 0..250 {
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
    assert_eq!(imbalance.worker_count, 4);
    assert_eq!(imbalance.total_calls, 1_000);
    assert_eq!(imbalance.max_share_ppm, 250_000);
    assert_eq!(imbalance.median_share_ppm, 250_000);
    assert_eq!(imbalance.idle_share_ppm, 0);
}

/// One worker doing all work must saturate every share at one million ppm.
#[test]
fn single_worker_saturates_all_shares() {
    let runtime = Runtime::new();
    runtime.scope(|| {
        for _ in 0..50 {
            drop(span(Stage::Preprocess));
        }
    });

    let imbalance = runtime.take_session_worker_imbalance();
    assert_eq!(imbalance.worker_count, 1);
    assert_eq!(imbalance.total_calls, 50);
    assert_eq!(imbalance.max_share_ppm, 1_000_000);
    assert_eq!(imbalance.median_share_ppm, 1_000_000);
    assert_eq!(imbalance.idle_share_ppm, 0);
    assert_eq!(imbalance.workers[0].worker_id, 1);
    assert_eq!(imbalance.workers[0].calls, 50);
}

/// A runtime with no workers must report a zeroed record instead of dividing
/// by zero.
#[test]
fn empty_runtime_reports_zeroed_imbalance() {
    let runtime = Runtime::new();
    let imbalance = runtime.take_session_worker_imbalance();
    assert_eq!(imbalance.worker_count, 0);
    assert_eq!(imbalance.total_calls, 0);
    assert_eq!(imbalance.total_elapsed_ns, 0);
    assert_eq!(imbalance.max_share_ppm, 0);
    assert_eq!(imbalance.median_share_ppm, 0);
    assert_eq!(imbalance.idle_share_ppm, 0);
    assert!(imbalance.workers.is_empty());
}

/// Registered shards that execute nothing must still appear as idle workers
/// so stolen-work diagnosis sees the full worker pool.
#[test]
fn idle_registered_workers_are_visible_in_worker_records() {
    let runtime = Runtime::new();
    let busy = runtime.clone();
    let busy_worker = std::thread::spawn(move || {
        busy.scope(|| {
            for _ in 0..10 {
                drop(span(Stage::Decode));
            }
        });
    });
    let idle = runtime.clone();
    let idle_worker = std::thread::spawn(move || {
        idle.scope(|| {
            // Register the shard without recording any work.
        });
    });
    busy_worker.join().expect("busy worker completes");
    idle_worker.join().expect("idle worker completes");

    let imbalance = runtime.take_session_worker_imbalance();
    assert_eq!(imbalance.worker_count, 2);
    assert_eq!(imbalance.total_calls, 10);
    assert_eq!(imbalance.max_share_ppm, 1_000_000);
    // Upper median of per-worker calls [0, 10] is 10, the full call total.
    assert_eq!(imbalance.median_share_ppm, 1_000_000);
    assert_eq!(imbalance.idle_share_ppm, 500_000);
    let mut calls: Vec<u64> = imbalance.workers.iter().map(|worker| worker.calls).collect();
    calls.sort_unstable();
    assert_eq!(calls, vec![0, 10]);
}
