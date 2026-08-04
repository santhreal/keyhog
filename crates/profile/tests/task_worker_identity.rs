//! Task and worker identity recorded on spans, events, and annotations.

use keyhog_profile::{
    current_task_id, instrument_future, record_annotation, record_event, set_task_id, span,
    AnnotationId, Evidence, EvidenceGap, EventId, MetricId, RunIdentity, RunState, Session,
    SpanRecordV2, Stage, WorkOrigin,
};
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

fn identity(name: &str) -> RunIdentity {
    RunIdentity::new("0.5.49", "detectors", "config", name, "test", "cpu-simd")
}

fn recorded(evidence: &Evidence<u64>) -> Option<u64> {
    match evidence {
        Evidence::Recorded { value } => Some(*value),
        Evidence::Unavailable { .. } => None,
    }
}

struct ThreadWake(std::thread::Thread);

impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

fn block_on<F>(future: F) -> F::Output
where
    F: Future,
{
    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::park(),
        }
    }
}

/// A caller-set task id must land on spans, events, and annotations, and the
/// worker id must name the registering shard so sharded executors can
/// attribute every record to an operating worker.
#[test]
fn spans_and_events_carry_task_and_worker_identity() {
    let session = Session::start(identity("identity-on-records")).expect("start profile");
    let runtime = session.runtime();
    assert_eq!(set_task_id(42), 0);
    assert_eq!(current_task_id(), 42);
    drop(span(Stage::SourceRead));
    record_event(EventId::CoverageGap, 3);
    record_annotation(AnnotationId::QueueDepth, 9);
    assert_eq!(set_task_id(0), 42);

    let (spans, dropped) = runtime.take_session_span_records();
    assert_eq!(dropped, 0);
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].version, 3);
    assert_eq!(recorded(&spans[0].task_id), Some(42));
    // The session thread registered the first shard at session start.
    assert_eq!(recorded(&spans[0].worker_id), Some(1));

    let (events, annotations, loss) = runtime.take_session_typed_events();
    assert_eq!(loss.capacity_drops(), 0);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].version, 2);
    assert_eq!(recorded(&events[0].task_id), Some(42));
    assert_eq!(recorded(&events[0].worker_id), Some(1));
    assert_eq!(annotations.len(), 1);
    assert_eq!(annotations[0].version, 2);
    assert_eq!(recorded(&annotations[0].task_id), Some(42));
    let _ = session.finish(RunState::Completed);
}

/// instrument_future must carry the task id across a spawn boundary so work
/// polled on a worker thread is attributed to the task that submitted it.
#[test]
fn task_identity_propagates_across_spawned_future() {
    let session = Session::start(identity("task-across-spawn")).expect("start profile");
    let runtime = session.runtime();
    set_task_id(7);
    let task = instrument_future(Stage::BackendDispatch, async {
        assert_eq!(current_task_id(), 7);
        drop(span(Stage::ConfirmedPatterns));
        record_event(EventId::Interrupted, 1);
    });
    set_task_id(0);
    std::thread::spawn(move || block_on(task))
        .join()
        .expect("worker completes");

    let (spans, dropped) = runtime.take_session_span_records();
    assert_eq!(dropped, 0);
    assert_eq!(spans.len(), 2);
    assert!(spans
        .iter()
        .all(|record| recorded(&record.task_id) == Some(7)));
    let root = spans
        .iter()
        .find(|record| record.metric_id == MetricId::BackendDispatch)
        .expect("async root");
    let child = spans
        .iter()
        .find(|record| record.metric_id == MetricId::ConfirmedPatterns)
        .expect("worker child");
    // Root recorded on the submitting thread; child on the worker thread.
    assert_ne!(
        recorded(&root.worker_id),
        recorded(&child.worker_id),
        "worker ids distinguish submitting and operating shards"
    );
    let (events, _, _) = runtime.take_session_typed_events();
    assert_eq!(events.len(), 1);
    assert_eq!(recorded(&events[0].task_id), Some(7));
    assert_eq!(
        recorded(&events[0].worker_id),
        recorded(&child.worker_id)
    );
    let _ = session.finish(RunState::Completed);
}

/// Records written without a task id must report unavailable evidence rather
/// than a fabricated zero identity.
#[test]
fn records_without_task_identity_report_unavailable() {
    let session = Session::start(identity("no-task")).expect("start profile");
    let runtime = session.runtime();
    drop(span(Stage::Entropy));
    record_event(EventId::CoverageGap, 1);

    let (spans, _) = runtime.take_session_span_records();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].task_id, Evidence::unavailable(EvidenceGap::Unavailable));
    let (events, _, _) = runtime.take_session_typed_events();
    assert_eq!(events[0].task_id, Evidence::unavailable(EvidenceGap::Unavailable));
    let _ = session.finish(RunState::Completed);
}

/// Spans recorded by a legacy schema (no worker_id or work_origin fields)
/// must decode with explicit legacy-gap evidence and a root work origin.
#[test]
fn legacy_span_json_decodes_with_defaulted_identity_fields() {
    let json = serde_json::json!({
        "version": 1,
        "span_id": 9,
        "parent_span_id": { "status": "unavailable", "reason": "unavailable" },
        "metric_id": "decode",
        "start_ns": 5,
        "inclusive_ns": 12,
        "exclusive_ns": 12,
        "thread_id": 3,
        "task_id": { "status": "unavailable", "reason": "unavailable" }
    });
    let record: SpanRecordV2 = serde_json::from_value(json).expect("decode legacy span");
    assert_eq!(record.version, 1);
    assert_eq!(
        record.worker_id,
        Evidence::unavailable(EvidenceGap::LegacyV1NotRecorded)
    );
    assert_eq!(record.work_origin, WorkOrigin::Root);
}

/// Worker identity must follow shard registration order: the first worker to
/// enter on a thread owns the next sequence, and identities stay stable for
/// the thread's lifetime.
#[test]
fn worker_identity_tracks_shard_registration_order() {
    let session = Session::start(identity("worker-order")).expect("start profile");
    let runtime = session.runtime();
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let runtime = runtime.clone();
            std::thread::spawn(move || {
                runtime.scope(|| {
                    drop(span(Stage::ResultMerge));
                });
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("worker completes");
    }
    drop(span(Stage::Reporting));

    let (spans, _) = runtime.take_session_span_records();
    assert_eq!(spans.len(), 3);
    let main_worker = spans
        .iter()
        .find(|record| record.metric_id == MetricId::Reporting)
        .and_then(|record| recorded(&record.worker_id))
        .expect("main worker id");
    assert_eq!(main_worker, 1);
    let mut worker_ids: Vec<u64> = spans
        .iter()
        .filter(|record| record.metric_id == MetricId::ResultMerge)
        .filter_map(|record| recorded(&record.worker_id))
        .collect();
    worker_ids.sort_unstable();
    assert_eq!(worker_ids, vec![2, 3]);
    let _ = session.finish(RunState::Completed);
}
