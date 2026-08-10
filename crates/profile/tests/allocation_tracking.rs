//! Allocator counting, per-stage ownership, and peak tracking with an
//! installed TrackingAllocator. Exactness comes from per-stage slots: only
//! code running inside a span of that stage can move its counters, and the
//! tests hold one process lock so no second test interleaves.

use keyhog_profile::{
    allocation_snapshot, reset_allocation_peaks, span, AllocationSnapshotV2, CollectorAvailability,
    CollectorId, Evidence, RunIdentity, RunState, Session, Stage, TrackingAllocator,
};
use std::sync::{Mutex, MutexGuard};

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator::new();

static ALLOCATION_TEST_LOCK: Mutex<()> = Mutex::new(());

fn lock() -> MutexGuard<'static, ()> {
    ALLOCATION_TEST_LOCK.lock().expect("allocation test lock")
}

fn session(name: &str) -> Session {
    Session::start(RunIdentity::new(
        "0.5.49",
        "detectors",
        "config",
        name,
        "test",
        "auto",
    ))
    .expect("start profile")
}

fn slot_delta(
    end: &AllocationSnapshotV2,
    start: &AllocationSnapshotV2,
    stage: Stage,
) -> (u64, u64) {
    (
        end.slot(stage).allocations - start.slot(stage).allocations,
        end.slot(stage)
            .allocated_bytes
            .saturating_sub(start.slot(stage).allocated_bytes),
    )
}

/// Without the feature the allocator must be a transparent pass-through: the
/// snapshot stays zeroed and the capability reports Disabled with the exact
/// remediation, never fabricated counts.
#[cfg(not(feature = "allocation-tracking"))]
#[test]
fn disabled_feature_reports_zeroed_snapshot_and_disabled_capability() {
    let _guard = lock();
    let _allocations = vec![Box::new([1_u8; 64]); 4];
    let snapshot = allocation_snapshot();
    assert!(!allocation_tracking_installed());
    assert_eq!(snapshot.allocations, 0);
    assert_eq!(snapshot.allocated_bytes, 0);
    assert_eq!(snapshot.live_bytes, 0);
    let profile = session("allocation-disabled").finish(RunState::Completed);
    let capability = profile
        .collectors
        .iter()
        .find(|capability| capability.collector == CollectorId::AllocationTracking)
        .expect("allocation capability present");
    assert_eq!(capability.availability, CollectorAvailability::Disabled);
    assert_eq!(
        capability.detail.as_deref(),
        Some("enable the keyhog-profile allocation-tracking feature")
    );
}

#[cfg(feature = "allocation-tracking")]
mod tracked {
    use super::*;
    use keyhog_profile::{CounterId, GaugeId, MetricId, MetricKind};

    /// A known allocation pattern inside one stage span must move that
    /// stage's counters by exactly the requested counts and bytes; freeing
    /// outside the stage must still debit the owning stage through the
    /// allocation header.
    #[test]
    fn allocator_counts_are_exact_on_known_pattern() {
        let _guard = lock();
        let session = session("allocation-exact");
        let start = allocation_snapshot();
        let payload_b;
        {
            let _decode = span(Stage::Decode);
            let payload_a = Box::new([7_u8; 1_000]);
            payload_b = Box::new([7_u8; 2_000]);
            let payload_c = vec![9_u8; 3_000];
            std::hint::black_box(&payload_a);

            let mid = allocation_snapshot();
            assert_eq!(slot_delta(&mid, &start, Stage::Decode), (3, 6_000));
            assert_eq!(
                mid.slot(Stage::Decode).live_bytes,
                start.slot(Stage::Decode).live_bytes + 6_000
            );

            drop(payload_a);
            drop(payload_c);
            let after_drops = allocation_snapshot();
            assert_eq!(
                after_drops.slot(Stage::Decode).live_bytes,
                start.slot(Stage::Decode).live_bytes + 2_000
            );
            assert_eq!(slot_delta(&after_drops, &start, Stage::Decode), (3, 6_000));
        }
        // Freed outside the allocating stage; ownership follows the header.
        drop(payload_b);
        let end = allocation_snapshot();
        assert_eq!(
            end.slot(Stage::Decode).live_bytes,
            start.slot(Stage::Decode).live_bytes
        );
        assert!(end.allocations - start.allocations >= 3);
        assert!(end.deallocations - start.deallocations >= 3);
        assert!(end.allocated_bytes - start.allocated_bytes >= 6_000);
        assert!(end.deallocated_bytes - start.deallocated_bytes >= 6_000);
        let profile = session.finish(RunState::Completed);
        let system = match &profile.system {
            Evidence::Recorded { value } => value,
            other => panic!("system evidence must be recorded: {other:?}"),
        };
        let totals = match &system.allocation.totals {
            Evidence::Recorded { value } => value,
            other => panic!("allocation totals must be recorded: {other:?}"),
        };
        assert!(totals.allocations >= 3);
        assert!(totals.allocated_bytes >= 6_000);
    }

    /// Per-stage ownership must attribute live bytes to the allocating stage
    /// even when the free runs inside a different stage on the same thread.
    #[test]
    fn ownership_follows_allocation_across_stage_boundaries() {
        let _guard = lock();
        let _session = session("allocation-ownership");
        let start = allocation_snapshot();
        // `vec![Box::new([u8; 512]); 4]` is exactly five allocations: the Vec's
        // four-pointer backing buffer (32 bytes on 64-bit) plus one 512-byte
        // box per element. 4 * 512 + 32 = 2080.
        let retained;
        {
            let _read = span(Stage::SourceRead);
            retained = vec![Box::new([3_u8; 512]); 4];
            let mid = allocation_snapshot();
            assert_eq!(slot_delta(&mid, &start, Stage::SourceRead), (5, 2_080));
            {
                let _report = span(Stage::Reporting);
                drop(retained);
            }
            let after_free = allocation_snapshot();
            assert_eq!(
                after_free.slot(Stage::SourceRead).live_bytes,
                start.slot(Stage::SourceRead).live_bytes
            );
            assert_eq!(
                after_free.slot(Stage::Reporting).live_bytes,
                start.slot(Stage::Reporting).live_bytes
            );
        }
        let end = allocation_snapshot();
        assert_eq!(slot_delta(&end, &start, Stage::SourceRead), (5, 2_080));
    }

    /// The per-stage peak must equal the exact maximum live bytes of a known
    /// growth pattern measured from a reset baseline.
    #[test]
    fn per_stage_peak_is_exact_on_known_growth() {
        let _guard = lock();
        let _session = session("allocation-peak");
        reset_allocation_peaks();
        let start = allocation_snapshot();
        let baseline_live = start.slot(Stage::Entropy).live_bytes;
        let keep;
        {
            let _entropy = span(Stage::Entropy);
            let first = vec![1_u8; 4_096];
            let second = vec![2_u8; 8_192];
            std::hint::black_box(&first);
            std::hint::black_box(&second);
            let mid = allocation_snapshot();
            assert_eq!(mid.slot(Stage::Entropy).live_bytes, baseline_live + 12_288);
            assert_eq!(
                mid.slot(Stage::Entropy).peak_live_bytes,
                baseline_live + 12_288
            );
            drop(second);
            keep = first;
        }
        let end = allocation_snapshot();
        assert_eq!(end.slot(Stage::Entropy).live_bytes, baseline_live + 4_096);
        // The peak survives the drop exactly.
        assert_eq!(
            end.slot(Stage::Entropy).peak_live_bytes,
            baseline_live + 12_288
        );
        assert!(end.peak_live_bytes >= end.live_bytes);
        drop(keep);
    }

    /// A finished session must expose allocation totals in the system
    /// evidence and as typed session counters and gauges.
    #[test]
    fn session_records_allocation_totals_as_typed_metrics() {
        let _guard = lock();
        let session = session("allocation-typed");
        let runtime = session.runtime();
        {
            let _merge = span(Stage::ResultMerge);
            let held = vec![5_u8; 1_024];
            std::hint::black_box(&held);
        }
        let profile = session.finish(RunState::Completed);
        let capability = profile
            .collectors
            .iter()
            .find(|capability| capability.collector == CollectorId::AllocationTracking)
            .expect("allocation capability present");
        assert_eq!(capability.availability, CollectorAvailability::Available);

        let system = match &profile.system {
            Evidence::Recorded { value } => value,
            other => panic!("system evidence must be recorded: {other:?}"),
        };
        let totals = match &system.allocation.totals {
            Evidence::Recorded { value } => value,
            other => panic!("allocation totals must be recorded: {other:?}"),
        };
        let merge = system
            .allocation
            .stages
            .iter()
            .find(|stage| stage.metric_id == Some(MetricId::ResultMerge))
            .expect("result-merge stage entry");
        assert_eq!(
            (merge.allocations, merge.allocated_bytes),
            (1, 1_024),
            "the only allocation inside the ResultMerge span is the 1 KiB vec"
        );
        // The root slot owns everything allocated outside a stage span: session
        // startup, snapshotting, and profile construction all live there, so it
        // is never empty. What must hold is conservation: every allocation is
        // attributed to exactly one slot, so the slots sum to the totals.
        let root = system
            .allocation
            .stages
            .iter()
            .find(|stage| stage.metric_id.is_none())
            .expect("root stage entry");
        assert!(
            root.allocations > 0,
            "session startup allocates outside any stage span"
        );
        let summed: u64 = system
            .allocation
            .stages
            .iter()
            .map(|stage| stage.allocations)
            .sum();
        assert_eq!(
            summed, totals.allocations,
            "per-stage attribution must neither lose nor double-count an allocation"
        );
        let summed_bytes: u64 = system
            .allocation
            .stages
            .iter()
            .map(|stage| stage.allocated_bytes)
            .sum();
        assert_eq!(
            summed_bytes, totals.allocated_bytes,
            "per-stage byte attribution must sum to the recorded total"
        );
        let summed_live_bytes: u64 = system
            .allocation
            .stages
            .iter()
            .map(|stage| stage.live_bytes)
            .sum();
        assert_eq!(
            summed_live_bytes, totals.live_bytes,
            "every retained allocation must have exactly one stage or root owner"
        );

        let typed = runtime.take_session_typed_metrics();
        let find = |metric: MetricId| {
            typed
                .iter()
                .find(|record| record.metric_id == metric)
                .map(|record| record.value)
        };
        assert_eq!(find(MetricId::AllocationCount), Some(totals.allocations));
        assert_eq!(
            find(MetricId::AllocationBytes),
            Some(totals.allocated_bytes)
        );
        assert_eq!(find(MetricId::AllocationLiveBytes), Some(totals.live_bytes));
        assert_eq!(
            find(MetricId::AllocationPeakLiveBytes),
            Some(totals.peak_live_bytes)
        );
        let counter = CounterId::AllocationCount;
        assert_eq!(counter.metric_id(), MetricId::AllocationCount);
        let gauge = GaugeId::AllocationPeakLiveBytes;
        assert_eq!(gauge.metric_id(), MetricId::AllocationPeakLiveBytes);
        let live_record = typed
            .iter()
            .find(|record| record.metric_id == MetricId::AllocationLiveBytes)
            .expect("live gauge drained");
        assert_eq!(live_record.kind, MetricKind::Gauge);
    }
}

#[test]
fn corrupt_header_stage_does_not_panic_on_dealloc() {
    let _guard = lock();
    use std::alloc::{GlobalAlloc, Layout};

    let layout = Layout::from_size_align(64, 8).expect("layout");
    let ptr = unsafe { ALLOCATOR.alloc(layout) };
    assert!(!ptr.is_null(), "alloc must succeed");

    // AllocationHeader is #[repr(C)] { stage: u8, magic: u8, ... }. Overwrite
    // stage with an out-of-range slot; release builds previously indexed SLOT_*
    // with that value and panicked inside the global allocator.
    let offset = layout.align().max(16);
    unsafe {
        let header = ptr.sub(offset);
        header.write(0xFF);
    }

    unsafe { ALLOCATOR.dealloc(ptr, layout) };
}

#[test]
fn corrupt_header_magic_does_not_panic_on_dealloc() {
    let _guard = lock();
    use std::alloc::{GlobalAlloc, Layout};

    let layout = Layout::from_size_align(32, 8).expect("layout");
    let ptr = unsafe { ALLOCATOR.alloc(layout) };
    assert!(!ptr.is_null(), "alloc must succeed");

    let offset = layout.align().max(16);
    unsafe {
        // stage stays plausible; magic is second byte.
        ptr.sub(offset).add(1).write(0x00);
    }

    unsafe { ALLOCATOR.dealloc(ptr, layout) };
}
