//! Producer-consumer causality links through bounded queues.

use keyhog_profile::{
    record_queue_dequeue, record_queue_enqueue, QueueId, RunIdentity, RunState, Session,
    MAX_QUEUE_LINKS,
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

/// Every matched enqueue/dequeue pair must produce one link carrying both
/// thread identities in stable (queue, sequence) order, proving the consumer
/// observed exactly what the producer published.
#[test]
fn matched_pairs_produce_links_with_both_thread_identities() {
    let session = session("matched-links");
    let runtime = session.runtime();
    let producer_runtime = runtime.clone();
    let producer = std::thread::spawn(move || {
        producer_runtime.scope(|| {
            for sequence in 0..100_u64 {
                record_queue_enqueue(QueueId::ScannerWork, sequence);
            }
        });
    });
    producer.join().expect("producer completes");
    for sequence in 0..100_u64 {
        record_queue_dequeue(QueueId::ScannerWork, sequence);
    }

    let (links, loss) = runtime.take_session_queue_links();
    assert_eq!(links.len(), 100);
    assert_eq!(loss.dropped_enqueues, 0);
    assert_eq!(loss.dropped_links, 0);
    assert_eq!(loss.unmatched_dequeues, 0);
    assert_eq!(loss.unconsumed_enqueues, 0);
    for (index, link) in links.iter().enumerate() {
        assert_eq!(link.version, 1);
        assert_eq!(link.queue, QueueId::ScannerWork);
        assert_eq!(link.sequence, index as u64);
        assert_eq!(link.producer_thread_id, links[0].producer_thread_id);
        assert_eq!(link.consumer_thread_id, links[0].consumer_thread_id);
        assert_ne!(link.producer_thread_id, link.consumer_thread_id);
        assert!(link.producer_elapsed_ns <= link.consumer_elapsed_ns);
    }
    let _ = session.finish(RunState::Completed);
}

/// Interleaved sequences across two queues must match strictly per
/// (queue, sequence) key rather than by arrival order.
#[test]
fn links_match_per_queue_and_sequence_not_arrival_order() {
    let session = session("per-queue-matching");
    let runtime = session.runtime();
    for sequence in 0..10_u64 {
        record_queue_enqueue(QueueId::SourceWork, sequence);
        record_queue_enqueue(QueueId::BackendBatch, sequence + 100);
    }
    for sequence in (0..10_u64).rev() {
        record_queue_dequeue(QueueId::BackendBatch, sequence + 100);
        record_queue_dequeue(QueueId::SourceWork, sequence);
    }

    let (links, loss) = runtime.take_session_queue_links();
    assert_eq!(links.len(), 20);
    assert_eq!(loss.unmatched_dequeues, 0);
    assert_eq!(loss.unconsumed_enqueues, 0);
    // Sorted by (queue, sequence): SourceWork < BackendBatch by enum order.
    assert!(links[..10]
        .iter()
        .all(|link| link.queue == QueueId::SourceWork));
    assert!(links[10..]
        .iter()
        .all(|link| link.queue == QueueId::BackendBatch));
    assert_eq!(links[0].sequence, 0);
    assert_eq!(links[10].sequence, 100);
    let _ = session.finish(RunState::Completed);
}

/// A dequeue with no recorded enqueue must be counted as unmatched instead of
/// fabricating a link with a missing producer.
#[test]
fn unmatched_dequeue_is_counted_not_linked() {
    let session = session("unmatched-dequeue");
    let runtime = session.runtime();
    record_queue_enqueue(QueueId::SourceWork, 1);
    record_queue_dequeue(QueueId::SourceWork, 1);
    record_queue_dequeue(QueueId::SourceWork, 77);
    record_queue_dequeue(QueueId::DecoderWork, 1);

    let (links, loss) = runtime.take_session_queue_links();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].sequence, 1);
    assert_eq!(loss.unmatched_dequeues, 2);
    assert_eq!(loss.unconsumed_enqueues, 0);
    let _ = session.finish(RunState::Completed);
}

/// Pending-enqueue retention must stop exactly at its bound, reporting
/// overflow as dropped and the remainder as unconsumed at drain.
#[test]
fn pending_enqueue_capacity_reports_exact_drop_and_unconsumed_counts() {
    let session = session("pending-capacity");
    let runtime = session.runtime();
    for sequence in 0..(MAX_QUEUE_LINKS as u64 + 5) {
        record_queue_enqueue(QueueId::DecoderWork, sequence);
    }

    let (links, loss) = runtime.take_session_queue_links();
    assert!(links.is_empty());
    assert_eq!(loss.dropped_enqueues, 5);
    assert_eq!(loss.unconsumed_enqueues, MAX_QUEUE_LINKS as u64);
    assert_eq!(loss.unmatched_dequeues, 0);
    assert_eq!(loss.dropped_links, 0);
    let _ = session.finish(RunState::Completed);
}

/// A duplicate (queue, sequence) enqueue must displace the earlier pending
/// record and count the displacement so one item never links twice.
#[test]
fn duplicate_sequence_displaces_and_counts_earlier_enqueue() {
    let session = session("duplicate-sequence");
    let runtime = session.runtime();
    record_queue_enqueue(QueueId::ResultMerge, 7);
    record_queue_enqueue(QueueId::ResultMerge, 7);
    record_queue_dequeue(QueueId::ResultMerge, 7);

    let (links, loss) = runtime.take_session_queue_links();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].sequence, 7);
    assert_eq!(loss.dropped_enqueues, 1);
    assert_eq!(loss.unconsumed_enqueues, 0);
    assert_eq!(loss.unmatched_dequeues, 0);
    let _ = session.finish(RunState::Completed);
}

/// Draining must reset retention and loss counters so the next interval
/// starts from an exact empty baseline.
#[test]
fn drain_resets_link_storage_and_loss_counters() {
    let session = session("drain-reset");
    let runtime = session.runtime();
    record_queue_enqueue(QueueId::LiveVerification, 1);
    let (_, first_loss) = runtime.take_session_queue_links();
    assert_eq!(first_loss.unconsumed_enqueues, 1);

    record_queue_enqueue(QueueId::LiveVerification, 2);
    record_queue_dequeue(QueueId::LiveVerification, 2);
    let (links, second_loss) = runtime.take_session_queue_links();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].sequence, 2);
    assert_eq!(second_loss.unconsumed_enqueues, 0);
    assert_eq!(second_loss.dropped_enqueues, 0);
    let _ = session.finish(RunState::Completed);
}
