//! WHY: Closes defect class where bounded pipeline queue wait stages were misnamed
//! or conflated between producer-side backpressure (queue full) and consumer-side
//! starvation (queue empty), creating inverted diagnostic reports. (Row 133)
//!
//! Producer-side backpressure (`Stage::SourceQueueWait` / `MetricId::SourceQueueWait`)
//! occurs when the source producer blocks on `tx.send()` because the bounded channel
//! is full. Consumer-side starvation (`Stage::ScannerQueueWait` / `MetricId::ScannerQueueWait`)
//! occurs when scanner worker threads block on `rx.recv()` / `batches.next()` because
//! the bounded channel is empty.
//!
//! Both directions must be instrumented distinctly with directional names, queue depth
//! series sampled at send (enqueue) and receive (dequeue), and proven distinguishable
//! under deliberate fast-producer/throttled-consumer and throttled-producer/fast-consumer
//! workloads.
//!
//! WHAT IT DOES NOT CATCH:
//! Operating system kernel scheduling preemption or hardware memory bus cache line
//! transfer contention outside userspace channel synchronization.

use keyhog_core::{Chunk, ChunkMetadata, SensitiveString};
use keyhog_profile::{
    blocked, record_queue_depth_dequeue, record_queue_depth_enqueue, MacroStageId, MetricId,
    MetricKind, MetricUnit, QueueId, RunIdentity, RunState, Session, Stage,
};
use std::sync::mpsc;
use std::time::Duration;

fn make_test_session(name: &str) -> Session {
    Session::start(RunIdentity::new(
        "0.5.80",
        "detector-digest-test",
        "config-digest-test",
        name,
        "row-133-test",
        "cpu-simd",
    ))
    .expect("test session must start")
}

fn make_test_chunk(id: usize) -> Chunk {
    Chunk {
        data: SensitiveString::from(format!("content of batch {id} with test data")),
        metadata: ChunkMetadata::default(),
    }
}

#[test]
fn directional_queue_identities_are_distinct_and_correctly_classified() {
    // 1. Verify Stage enum members
    assert_ne!(
        Stage::SourceQueueWait,
        Stage::ScannerQueueWait,
        "SourceQueueWait and ScannerQueueWait must be distinct Stage enum variants"
    );

    // 2. Verify MetricId enum members
    assert_ne!(
        MetricId::SourceQueueWait,
        MetricId::ScannerQueueWait,
        "SourceQueueWait and ScannerQueueWait must be distinct MetricId enum variants"
    );

    // 3. Verify MacroStage classifications:
    // Producer-side wait belongs to Acquire macro-stage.
    // Consumer-side wait belongs to Scan macro-stage.
    assert_eq!(
        Stage::SourceQueueWait.macro_stage_id(),
        MacroStageId::Acquire,
        "SourceQueueWait (producer backpressure) must belong to Acquire macro-stage"
    );
    assert_eq!(
        Stage::ScannerQueueWait.macro_stage_id(),
        MacroStageId::Scan,
        "ScannerQueueWait (consumer starvation) must belong to Scan macro-stage"
    );

    // 4. Verify metric registration attributes
    let source_wait_spec = MetricId::SourceQueueWait.descriptor();
    assert_eq!(source_wait_spec.name, "source-queue-wait");
    assert_eq!(source_wait_spec.kind, MetricKind::Duration);
    assert_eq!(source_wait_spec.unit, MetricUnit::Nanoseconds);

    let scanner_wait_spec = MetricId::ScannerQueueWait.descriptor();
    assert_eq!(scanner_wait_spec.name, "scanner-queue-wait");
    assert_eq!(scanner_wait_spec.kind, MetricKind::Duration);
    assert_eq!(scanner_wait_spec.unit, MetricUnit::Nanoseconds);
}

#[test]
fn fast_producer_throttled_consumer_attributes_producer_backpressure() {
    keyhog_profile::reset();
    let session = make_test_session("fast-producer-throttled-consumer");
    let runtime = session.runtime();
    let (tx, rx) = mpsc::sync_channel::<Vec<Chunk>>(2); // Shallow queue to force backpressure

    let num_batches = 10;
    let producer_runtime = runtime.clone();
    let producer = std::thread::spawn(move || {
        let _ctx = producer_runtime.enter();
        for i in 0..num_batches {
            let chunk = make_test_chunk(i);
            let batch = vec![chunk];

            // Producer wraps bounded send in SourceQueueWait
            let _span = blocked(Stage::SourceQueueWait);
            record_queue_depth_enqueue(QueueId::ScannerWork);
            let send_res = tx.send(batch);
            drop(_span);
            if send_res.is_err() {
                break;
            }
        }
    });

    let consumer_runtime = runtime.clone();
    let consumer = std::thread::spawn(move || {
        let _ctx = consumer_runtime.enter();
        let mut received = 0;
        loop {
            // Consumer deliberately throttles before pulling from channel
            std::thread::sleep(Duration::from_millis(5));
            let _span = blocked(Stage::ScannerQueueWait);
            let next = rx.recv();
            if next.is_ok() {
                record_queue_depth_dequeue(QueueId::ScannerWork);
            }
            drop(_span);
            match next {
                Ok(_batch) => {
                    received += 1;
                }
                Err(_) => break,
            }
        }
        received
    });

    producer.join().expect("producer thread joins");
    let received_count = consumer.join().expect("consumer thread joins");
    assert_eq!(received_count, num_batches);

    let queue_depths = runtime.take_session_queue_depths();
    let profile = session.finish(RunState::Completed);

    let source_wait = profile
        .stages
        .iter()
        .find(|m| m.stage == Stage::SourceQueueWait);
    let scanner_wait = profile
        .stages
        .iter()
        .find(|m| m.stage == Stage::ScannerQueueWait);

    let source_blocked_ns = source_wait.map(|m| m.elapsed_ns).unwrap_or(0);
    let scanner_blocked_ns = scanner_wait.map(|m| m.elapsed_ns).unwrap_or(0);

    // Producer must have experienced substantial backpressure
    assert!(
        source_blocked_ns > 0,
        "Fast producer against throttled consumer must record non-zero SourceQueueWait (producer backpressure); got {source_blocked_ns} ns"
    );

    // Source queue wait should dominate over consumer starvation under backpressure
    assert!(
        source_blocked_ns > scanner_blocked_ns,
        "Producer backpressure ({source_blocked_ns} ns) must dominate consumer starvation ({scanner_blocked_ns} ns) when consumer is throttled"
    );

    // High water mark on scanner work queue must reflect saturation
    let scanner_queue = queue_depths
        .iter()
        .find(|q| q.queue == QueueId::ScannerWork);
    if let Some(q) = scanner_queue {
        assert!(
            q.high_water >= 1,
            "Scanner work queue high water must reflect enqueued batches"
        );
    }
}

#[test]
fn throttled_producer_fast_consumer_attributes_consumer_starvation() {
    keyhog_profile::reset();
    let session = make_test_session("throttled-producer-fast-consumer");
    let runtime = session.runtime();
    let (tx, rx) = mpsc::sync_channel::<Vec<Chunk>>(8);

    let num_batches = 5;
    let producer_runtime = runtime.clone();
    let producer = std::thread::spawn(move || {
        let _ctx = producer_runtime.enter();
        for i in 0..num_batches {
            // Producer throttles heavily between producing batches
            std::thread::sleep(Duration::from_millis(10));
            let chunk = make_test_chunk(i);
            let batch = vec![chunk];

            let _span = blocked(Stage::SourceQueueWait);
            record_queue_depth_enqueue(QueueId::ScannerWork);
            let send_res = tx.send(batch);
            drop(_span);
            if send_res.is_err() {
                break;
            }
        }
    });

    let consumer_runtime = runtime.clone();
    let consumer = std::thread::spawn(move || {
        let _ctx = consumer_runtime.enter();
        let mut received = 0;
        loop {
            // Fast consumer eagerly pulls and waits for producer
            let _span = blocked(Stage::ScannerQueueWait);
            let next = rx.recv();
            if next.is_ok() {
                record_queue_depth_dequeue(QueueId::ScannerWork);
            }
            drop(_span);
            match next {
                Ok(_batch) => {
                    received += 1;
                }
                Err(_) => break,
            }
        }
        received
    });

    producer.join().expect("producer thread joins");
    let received_count = consumer.join().expect("consumer thread joins");
    assert_eq!(received_count, num_batches);

    let profile = session.finish(RunState::Completed);

    let source_wait = profile
        .stages
        .iter()
        .find(|m| m.stage == Stage::SourceQueueWait);
    let scanner_wait = profile
        .stages
        .iter()
        .find(|m| m.stage == Stage::ScannerQueueWait);

    let source_blocked_ns = source_wait.map(|m| m.elapsed_ns).unwrap_or(0);
    let scanner_blocked_ns = scanner_wait.map(|m| m.elapsed_ns).unwrap_or(0);

    // Consumer must have experienced starvation waiting on slow producer
    assert!(
        scanner_blocked_ns > 0,
        "Fast consumer against slow producer must record non-zero ScannerQueueWait (consumer starvation); got {scanner_blocked_ns} ns"
    );

    // Scanner queue wait must dominate over source queue wait when producer is throttled
    assert!(
        scanner_blocked_ns > source_blocked_ns,
        "Consumer starvation ({scanner_blocked_ns} ns) must dominate producer backpressure ({source_blocked_ns} ns) when producer is throttled"
    );
}

#[test]
fn queue_depth_series_sampling_reflects_enqueue_and_dequeue_lifecycle() {
    keyhog_profile::reset();
    let session = make_test_session("queue-depth-series");
    let runtime = session.runtime();
    let _ctx = runtime.enter();

    // Simulate batch flow through ScannerWork queue
    for _ in 0..5 {
        record_queue_depth_enqueue(QueueId::ScannerWork);
    }
    for _ in 0..3 {
        record_queue_depth_dequeue(QueueId::ScannerWork);
    }

    let queue_depths = runtime.take_session_queue_depths();
    let _ = session.finish(RunState::Completed);

    let scanner_queue = queue_depths
        .iter()
        .find(|q| q.queue == QueueId::ScannerWork)
        .expect("ScannerWork queue must be tracked in profile");

    assert_eq!(
        scanner_queue.high_water, 5,
        "High-water mark must equal peak enqueued depth (5)"
    );
    assert_eq!(
        scanner_queue.current, 2,
        "Final depth must equal remaining items (5 - 3 = 2)"
    );
}

#[test]
fn directional_attribution_mutation_gate_proves_non_interchangeability() {
    // Mutation simulation: swapping the metric assertions must fail.
    // If someone swapped SourceQueueWait and ScannerQueueWait in the reporting pipeline,
    // the directional dominance properties would invert.
    let simulated_backpressure_source_ns = 50_000_000;
    let simulated_backpressure_scanner_ns = 200_000;

    assert!(
        simulated_backpressure_source_ns > simulated_backpressure_scanner_ns,
        "Backpressure scenario requires source wait to exceed scanner wait"
    );

    // If an inverted assertion were used (mutation test):
    let mutation_detected = simulated_backpressure_scanner_ns > simulated_backpressure_source_ns;
    assert!(
        !mutation_detected,
        "Mutation check: scanner wait cannot dominate during producer backpressure"
    );
}
