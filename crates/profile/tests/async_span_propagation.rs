use keyhog_profile::{
    current_runtime, enabled, instrument_future, span, Evidence, MetricId, RunIdentity, RunState,
    Session, Stage,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

fn identity(name: &str) -> RunIdentity {
    RunIdentity::new("0.5.49", "detectors", "config", name, "test", "cpu-simd")
}

fn parent_id(evidence: &Evidence<u64>) -> Option<u64> {
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

struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.0 {
            self.0 = false;
            context.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
}

struct PendingForever;

impl Future for PendingForever {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

/// Runtime context must be restored on every poll so spans after an await stay in the same run.
#[test]
fn runtime_and_parent_propagate_across_pending_await() {
    let session = Session::start(identity("await-boundary")).expect("start profile");
    let runtime = session.runtime();
    block_on(instrument_future(Stage::SourceAcquire, async {
        assert!(enabled());
        assert!(current_runtime().is_some());
        drop(span(Stage::SourceRead));
        YieldOnce(true).await;
        assert!(enabled());
        assert!(current_runtime().is_some());
        drop(span(Stage::SourceRead));
    }));

    let (records, dropped) = runtime.take_session_span_records();
    assert_eq!(dropped, 0);
    assert_eq!(records.len(), 3);
    let root = records
        .iter()
        .find(|record| record.metric_id == MetricId::SourceAcquire)
        .expect("async root span");
    let children: Vec<_> = records
        .iter()
        .filter(|record| record.metric_id == MetricId::SourceRead)
        .collect();
    assert_eq!(children.len(), 2);
    assert!(children
        .iter()
        .all(|child| parent_id(&child.parent_span_id) == Some(root.span_id)));
    assert_eq!(
        root.exclusive_ns,
        root.inclusive_ns
            .saturating_sub(children.iter().map(|child| child.inclusive_ns).sum())
    );
    let _ = session.finish(RunState::Completed);
}

/// A sendable future may migrate to another thread without losing its originating runtime.
#[test]
fn send_future_propagates_runtime_to_worker_thread() {
    let session = Session::start(identity("worker-migration")).expect("start profile");
    let runtime = session.runtime();
    let task = instrument_future(Stage::BackendDispatch, async {
        assert!(enabled());
        YieldOnce(true).await;
        drop(span(Stage::ConfirmedPatterns));
    });
    std::thread::spawn(move || block_on(task))
        .join()
        .expect("join async worker");

    let (records, dropped) = runtime.take_session_span_records();
    assert_eq!(dropped, 0);
    assert_eq!(records.len(), 2);
    let root = records
        .iter()
        .find(|record| record.metric_id == MetricId::BackendDispatch)
        .expect("async root span");
    let child = records
        .iter()
        .find(|record| record.metric_id == MetricId::ConfirmedPatterns)
        .expect("worker child span");
    assert_eq!(parent_id(&child.parent_span_id), Some(root.span_id));
    assert_ne!(root.thread_id, child.thread_id);
    assert_eq!(runtime.worker_shard_count(), 2);
    let _ = session.finish(RunState::Completed);
}

/// Nested instrumented futures must form one causal chain rather than unrelated root spans.
#[test]
fn nested_instrumented_futures_preserve_causal_chain() {
    let session = Session::start(identity("nested-async")).expect("start profile");
    let runtime = session.runtime();
    block_on(instrument_future(Stage::SourceAcquire, async {
        instrument_future(Stage::Preprocess, async {
            drop(span(Stage::Decode));
        })
        .await;
    }));

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
    let _ = session.finish(RunState::Completed);
}

/// Dropping a future after its first pending poll must close its async span instead of leaking detail.
#[test]
fn cancellation_after_first_poll_closes_async_span() {
    let session = Session::start(identity("cancelled-async")).expect("start profile");
    let runtime = session.runtime();
    let mut task = Box::pin(instrument_future(Stage::LiveVerification, PendingForever));
    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    assert!(task.as_mut().poll(&mut context).is_pending());
    drop(task);

    let (records, dropped) = runtime.take_session_span_records();
    assert_eq!(dropped, 0);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].metric_id, MetricId::LiveVerification);
    assert_eq!(records[0].exclusive_ns, records[0].inclusive_ns);
    let _ = session.finish(RunState::Completed);
}

/// Disabled instrumentation must execute the future without creating spans or runtime context.
#[test]
fn disabled_wrapper_executes_without_recording() {
    let observed = block_on(instrument_future(Stage::SourceRead, async {
        assert!(!enabled());
        assert!(current_runtime().is_none());
        42_u64
    }));
    assert_eq!(observed, 42);
}
