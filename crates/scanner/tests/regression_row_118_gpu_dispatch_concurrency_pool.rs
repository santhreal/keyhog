//! WHY: Closes the defect class where GPU region-presence dispatch was serialized
//! behind a single process-wide Mutex<()> on the CLI path, enforcing concurrency 1.00
//! regardless of host thread count and device capability (Row 118).
//! Both CLI and daemon paths now use a shared resident accelerator execution pool.
//!
//! What this does NOT catch: physical PCIe bus queue serialization inside kernel drivers.

#[cfg(feature = "gpu")]
use keyhog_scanner::testing::GpuResidentExecutionPool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

#[cfg(feature = "gpu")]
#[test]
fn row_118_pool_concurrency_scales_with_capacity_under_contention() {
    let capacity = 4;
    let pool = Arc::new(GpuResidentExecutionPool::new(capacity));

    assert_eq!(pool.capacity(), capacity);
    assert_eq!(pool.in_flight(), 0);
    assert_eq!(pool.available_permits(), capacity);
    assert_eq!(pool.total_dispatches(), 0);

    let active_counter = Arc::new(AtomicUsize::new(0));
    let peak_counter = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(std::sync::Barrier::new(capacity));

    let mut handles = Vec::new();
    for _ in 0..capacity {
        let pool = Arc::clone(&pool);
        let active = Arc::clone(&active_counter);
        let peak = Arc::clone(&peak_counter);
        let barrier = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            let permit = pool.acquire_permit().expect("acquire permit");
            let curr = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(curr, Ordering::SeqCst);

            assert!(
                curr <= capacity,
                "active concurrency {curr} must not exceed pool capacity {capacity}"
            );

            barrier.wait();

            active.fetch_sub(1, Ordering::SeqCst);
            drop(permit);
        }));
    }

    for h in handles {
        h.join().expect("thread join");
    }

    let peak = peak_counter.load(Ordering::SeqCst);
    assert!(
        peak > 1,
        "under contention peak concurrency ({peak}) must exceed 1.0 (serialized)"
    );
    assert!(
        peak <= capacity,
        "peak concurrency ({peak}) must remain bounded by pool capacity ({capacity})"
    );
    assert_eq!(pool.in_flight(), 0);
    assert_eq!(pool.available_permits(), capacity);
    assert_eq!(pool.total_dispatches(), capacity as u64);
    assert_eq!(pool.peak_concurrency(), peak);
}

#[cfg(feature = "gpu")]
#[test]
fn row_118_capacity_derivation_deterministic_across_device_capabilities() {
    let caps = ["async-submit-retire", "single-resident-slot", "unknown"];
    for cap in caps {
        for depth in 1..=4u8 {
            for host_concurrency in [1, 2, 4, 8, 16, 32, 64] {
                let capacity = GpuResidentExecutionPool::derive_capacity_for_device(
                    cap,
                    depth,
                    host_concurrency,
                );
                assert!(
                    capacity >= 1,
                    "derived capacity must be positive for cap {cap}"
                );
                assert!(
                    capacity <= host_concurrency.max(1),
                    "derived capacity must not exceed host concurrency"
                );
            }
        }
    }
}
