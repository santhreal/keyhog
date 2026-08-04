//! Queue depth occupancy gauges and exact high-water marks.

use keyhog_profile::{
    record_queue_depth_dequeue, record_queue_depth_enqueue, set_queue_depth, QueueId, RunIdentity,
    RunState, Session,
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

/// Enqueue/dequeue deltas and explicit depth sets must produce exact current
/// depth, high-water, and operation totals per queue.
#[test]
fn depth_transitions_produce_exact_occupancy_records() {
    let session = session("depth-transitions");
    let runtime = session.runtime();
    for _ in 0..5 {
        record_queue_depth_enqueue(QueueId::ScannerWork);
    }
    for _ in 0..2 {
        record_queue_depth_dequeue(QueueId::ScannerWork);
    }
    set_queue_depth(QueueId::ScannerWork, 7);
    set_queue_depth(QueueId::ScannerWork, 1);

    let depths = runtime.take_session_queue_depths();
    assert_eq!(depths.len(), 1);
    let record = &depths[0];
    assert_eq!(record.version, 1);
    assert_eq!(record.queue, QueueId::ScannerWork);
    assert_eq!(record.current, 1);
    assert_eq!(record.high_water, 7);
    assert_eq!(record.enqueues, 5);
    assert_eq!(record.dequeues, 2);
    let _ = session.finish(RunState::Completed);
}

/// Only queues with observed activity may appear, and records must be ordered
/// by the stable queue slot index.
#[test]
fn only_active_queues_appear_in_stable_slot_order() {
    let session = session("active-queues");
    let runtime = session.runtime();
    record_queue_depth_enqueue(QueueId::ResultMerge);
    record_queue_depth_enqueue(QueueId::SourceWork);
    record_queue_depth_enqueue(QueueId::SourceWork);

    let depths = runtime.take_session_queue_depths();
    assert_eq!(depths.len(), 2);
    assert_eq!(depths[0].queue, QueueId::SourceWork);
    assert_eq!(depths[0].current, 2);
    assert_eq!(depths[0].high_water, 2);
    assert_eq!(depths[1].queue, QueueId::ResultMerge);
    assert_eq!(depths[1].current, 1);
    let _ = session.finish(RunState::Completed);
}

/// The high-water mark must survive depth decreases and must restart from the
/// current depth after a drain, so each interval's peak is exact.
#[test]
fn high_water_survives_decreases_and_resets_to_current_after_drain() {
    let session = session("high-water-reset");
    let runtime = session.runtime();
    set_queue_depth(QueueId::BackendBatch, 9);
    set_queue_depth(QueueId::BackendBatch, 3);
    let first = runtime.take_session_queue_depths();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].current, 3);
    assert_eq!(first[0].high_water, 9);

    set_queue_depth(QueueId::BackendBatch, 5);
    let second = runtime.take_session_queue_depths();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].current, 5);
    assert_eq!(second[0].high_water, 5);
    assert_eq!(second[0].enqueues, 0);
    assert_eq!(second[0].dequeues, 0);
    let _ = session.finish(RunState::Completed);
}

/// A dequeue from an empty queue must saturate at zero depth while still
/// counting the operation so consumer overruns stay visible.
#[test]
fn dequeue_from_empty_queue_saturates_and_counts() {
    let session = session("saturating-dequeue");
    let runtime = session.runtime();
    record_queue_depth_dequeue(QueueId::DecoderWork);
    record_queue_depth_dequeue(QueueId::DecoderWork);

    let depths = runtime.take_session_queue_depths();
    assert_eq!(depths.len(), 1);
    assert_eq!(depths[0].current, 0);
    assert_eq!(depths[0].high_water, 0);
    assert_eq!(depths[0].enqueues, 0);
    assert_eq!(depths[0].dequeues, 2);
    let _ = session.finish(RunState::Completed);
}

/// A drained queue that returned to zero depth must emit a final zeroed
/// record for the interval, then disappear once fully idle.
#[test]
fn emptied_queue_reports_final_zero_then_disappears() {
    let session = session("emptied-queue");
    let runtime = session.runtime();
    record_queue_depth_enqueue(QueueId::LiveVerification);
    record_queue_depth_dequeue(QueueId::LiveVerification);

    let first = runtime.take_session_queue_depths();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].current, 0);
    assert_eq!(first[0].high_water, 1);
    assert_eq!(first[0].enqueues, 1);
    assert_eq!(first[0].dequeues, 1);

    let second = runtime.take_session_queue_depths();
    assert!(second.is_empty());
    let _ = session.finish(RunState::Completed);
}
