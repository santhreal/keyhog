use keyhog_profile::{
    span, Evidence, MetricId, RunIdentity, RunState, Session, Stage, MAX_RECORDED_SPANS,
};
use std::time::Duration;

fn identity(name: &str) -> RunIdentity {
    RunIdentity::new("0.5.49", "detectors", "config", name, "test", "cpu-simd")
}

fn parent_id(evidence: &Evidence<u64>) -> Option<u64> {
    match evidence {
        Evidence::Recorded { value } => Some(*value),
        Evidence::Unavailable { .. } => None,
    }
}

/// A direct child must subtract its complete interval from its parent's exclusive time.
#[test]
fn direct_child_produces_exact_inclusive_and_exclusive_accounting() {
    let session = Session::start(identity("direct-child")).expect("start profile");
    let runtime = session.runtime();
    let outer = span(Stage::SourceAcquire);
    std::thread::sleep(Duration::from_millis(1));
    let child = span(Stage::SourceRead);
    std::thread::sleep(Duration::from_millis(2));
    drop(child);
    std::thread::sleep(Duration::from_millis(1));
    drop(outer);

    let (records, dropped) = runtime.take_session_span_records();
    assert_eq!(dropped, 0);
    assert_eq!(records.len(), 2);
    let parent = records
        .iter()
        .find(|record| record.metric_id == MetricId::SourceAcquire)
        .expect("parent span");
    let child = records
        .iter()
        .find(|record| record.metric_id == MetricId::SourceRead)
        .expect("child span");
    assert_eq!(parent_id(&parent.parent_span_id), None);
    assert_eq!(parent_id(&child.parent_span_id), Some(parent.span_id));
    assert_eq!(
        parent.exclusive_ns,
        parent.inclusive_ns - child.inclusive_ns
    );
    assert_eq!(child.exclusive_ns, child.inclusive_ns);
    assert!(parent.inclusive_ns >= child.inclusive_ns);
    assert!(parent.start_ns <= child.start_ns);
    assert_eq!(parent.thread_id, child.thread_id);
    assert_ne!(parent.thread_id, 0);
    let _ = session.finish(RunState::Completed);
}

/// Sibling intervals must each be subtracted once, without double-counting either child.
#[test]
fn siblings_are_subtracted_once_from_parent_exclusive_time() {
    let session = Session::start(identity("siblings")).expect("start profile");
    let runtime = session.runtime();
    let outer = span(Stage::BackendDispatch);
    let first = span(Stage::HotPatterns);
    std::thread::sleep(Duration::from_millis(1));
    drop(first);
    let second = span(Stage::ConfirmedPatterns);
    std::thread::sleep(Duration::from_millis(1));
    drop(second);
    drop(outer);

    let (records, dropped) = runtime.take_session_span_records();
    assert_eq!(dropped, 0);
    let parent = &records[0];
    let child_total: u64 = records[1..].iter().map(|record| record.inclusive_ns).sum();
    assert_eq!(records.len(), 3);
    assert_eq!(parent.exclusive_ns, parent.inclusive_ns - child_total);
    assert!(records[1..]
        .iter()
        .all(|record| parent_id(&record.parent_span_id) == Some(parent.span_id)));
    let _ = session.finish(RunState::Completed);
}

/// Three levels must subtract only each span's direct child so every interval has one owner.
#[test]
fn three_level_nesting_preserves_direct_parent_causality() {
    let session = Session::start(identity("three-level")).expect("start profile");
    let runtime = session.runtime();
    let root = span(Stage::Preprocess);
    let middle = span(Stage::Decode);
    let leaf = span(Stage::Entropy);
    std::thread::sleep(Duration::from_millis(1));
    drop(leaf);
    drop(middle);
    drop(root);

    let (records, dropped) = runtime.take_session_span_records();
    assert_eq!(dropped, 0);
    assert_eq!(records.len(), 3);
    assert_eq!(parent_id(&records[0].parent_span_id), None);
    assert_eq!(
        parent_id(&records[1].parent_span_id),
        Some(records[0].span_id)
    );
    assert_eq!(
        parent_id(&records[2].parent_span_id),
        Some(records[1].span_id)
    );
    assert_eq!(
        records[0].exclusive_ns,
        records[0].inclusive_ns - records[1].inclusive_ns
    );
    assert_eq!(
        records[1].exclusive_ns,
        records[1].inclusive_ns - records[2].inclusive_ns
    );
    assert_eq!(records[2].exclusive_ns, records[2].inclusive_ns);
    let _ = session.finish(RunState::Completed);
}

/// Worker roots must remain independent and carry distinct stable process-local thread identities.
#[test]
fn concurrent_worker_roots_do_not_invent_cross_thread_parentage() {
    let session = Session::start(identity("worker-roots")).expect("start profile");
    let runtime = session.runtime();
    let workers: Vec<_> = [Stage::SourceRead, Stage::BackendDispatch]
        .into_iter()
        .map(|stage| {
            let runtime = runtime.clone();
            std::thread::spawn(move || {
                runtime.scope(|| {
                    let _span = span(stage);
                    std::thread::sleep(Duration::from_millis(1));
                });
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("worker completes");
    }

    let (records, dropped) = runtime.take_session_span_records();
    assert_eq!(dropped, 0);
    assert_eq!(records.len(), 2);
    assert!(records
        .iter()
        .all(|record| parent_id(&record.parent_span_id).is_none()));
    assert_ne!(records[0].thread_id, records[1].thread_id);
    let _ = session.finish(RunState::Completed);
}

/// Non-lexical drops must saturate exclusive time instead of underflowing or corrupting later spans.
#[test]
fn out_of_order_drop_saturates_malformed_nesting_safely() {
    let session = Session::start(identity("out-of-order")).expect("start profile");
    let runtime = session.runtime();
    let parent = span(Stage::SourceAcquire);
    let child = span(Stage::SourceRead);
    drop(parent);
    std::thread::sleep(Duration::from_millis(1));
    drop(child);

    let (records, dropped) = runtime.take_session_span_records();
    assert_eq!(dropped, 0);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].exclusive_ns, 0);
    assert_eq!(
        parent_id(&records[1].parent_span_id),
        Some(records[0].span_id)
    );
    let _ = session.finish(RunState::Completed);
}

/// Finishing with a live guard must report that incomplete event instead of exporting zero duration.
#[test]
fn unfinished_span_is_omitted_and_counted_as_dropped() {
    let session = Session::start(identity("unfinished")).expect("start profile");
    let runtime = session.runtime();
    let unfinished = span(Stage::Reporting);
    let (records, dropped) = runtime.take_session_span_records();
    assert!(records.is_empty());
    assert_eq!(dropped, 1);
    drop(unfinished);
    let _ = session.finish(RunState::Completed);
}

/// The fixed causal stack must report depth overflow while retaining every representable ancestor.
#[test]
fn nesting_beyond_fixed_stack_is_loss_accounted() {
    let session = Session::start(identity("depth-cap")).expect("start profile");
    let runtime = session.runtime();
    let guards: Vec<_> = (0..65).map(|_| span(Stage::Decode)).collect();
    drop(guards);
    let (records, dropped) = runtime.take_session_span_records();
    assert_eq!(records.len(), 64);
    assert_eq!(dropped, 1);
    assert_eq!(parent_id(&records[0].parent_span_id), None);
    assert_eq!(
        parent_id(&records[63].parent_span_id),
        Some(records[62].span_id)
    );
    let _ = session.finish(RunState::Completed);
}

/// The retained event bound must be exact and must expose every omitted completed span.
#[test]
fn event_capacity_is_bounded_with_exact_dropped_count() {
    let session = Session::start(identity("event-cap")).expect("start profile");
    let runtime = session.runtime();
    for _ in 0..=MAX_RECORDED_SPANS {
        drop(span(Stage::GenericDetection));
    }
    let (records, dropped) = runtime.take_session_span_records();
    assert_eq!(records.len(), MAX_RECORDED_SPANS);
    assert_eq!(dropped, 1);
    assert_eq!(records.first().map(|record| record.span_id), Some(1));
    assert_eq!(
        records.last().map(|record| record.span_id),
        Some(MAX_RECORDED_SPANS as u64)
    );
    let _ = session.finish(RunState::Completed);
}
