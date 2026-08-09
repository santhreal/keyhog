//! Cross-boundary causal parent linkage through portable `CausalParent` tokens.

use keyhog_profile::{
    current_causal_parent, instrument_future_with_parent, span, span_with_parent, Evidence,
    MetricId, RunIdentity, RunState, Runtime, Session, Stage,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
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

/// A token carried across a thread boundary must link the child span to its
/// remote parent and subtract the child interval from the parent's exclusive
/// time, which thread-local parent lookup could never do on the worker thread.
#[test]
fn explicit_token_links_child_span_across_thread_boundary() {
    let session = Session::start(identity("token-cross-thread")).expect("start profile");
    let runtime = session.runtime();
    let outer = span(Stage::SourceAcquire);
    let token = current_causal_parent().expect("runtime captures token");
    assert!(!token.is_root());
    assert_eq!(token.context_id(), runtime.context_id());

    let worker_runtime = runtime.clone();
    let worker = std::thread::spawn(move || {
        worker_runtime.scope(|| {
            let child = span_with_parent(token, Stage::Decode);
            std::thread::sleep(Duration::from_millis(2));
            drop(child);
        });
    });
    worker.join().expect("worker completes");
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
        .find(|record| record.metric_id == MetricId::Decode)
        .expect("child span");
    assert_eq!(parent_id(&child.parent_span_id), Some(parent.span_id));
    assert_eq!(parent_id(&parent.parent_span_id), None);
    assert_eq!(
        parent.exclusive_ns,
        parent.inclusive_ns - child.inclusive_ns
    );
    assert_ne!(parent.thread_id, child.thread_id);
    let _ = session.finish(RunState::Completed);
}

/// A token captured inside nested spans must name the innermost live span so
/// later callers attach to the exact causal parent, not to an ancestor.
#[test]
fn captured_token_names_innermost_live_span() {
    let session = Session::start(identity("token-innermost")).expect("start profile");
    let runtime = session.runtime();
    let outer = span(Stage::SourceAcquire);
    let inner = span(Stage::Preprocess);
    let token = current_causal_parent().expect("runtime captures token");
    let child = span_with_parent(token, Stage::Entropy);
    drop(child);
    drop(inner);
    drop(outer);

    let (records, dropped) = runtime.take_session_span_records();
    assert_eq!(dropped, 0);
    assert_eq!(records.len(), 3);
    let inner_record = records
        .iter()
        .find(|record| record.metric_id == MetricId::Preprocess)
        .expect("inner span");
    let child_record = records
        .iter()
        .find(|record| record.metric_id == MetricId::Entropy)
        .expect("token child");
    assert_eq!(token.span_id(), inner_record.span_id);
    assert_eq!(
        parent_id(&child_record.parent_span_id),
        Some(inner_record.span_id)
    );
    assert_eq!(
        inner_record.exclusive_ns,
        inner_record.inclusive_ns - child_record.inclusive_ns
    );
    let _ = session.finish(RunState::Completed);
}

/// A token minted by a different runtime must not invent parentage: the span
/// records as a root of the runtime it actually executes in.
#[test]
fn foreign_runtime_token_records_root_instead_of_false_parent() {
    let session = Session::start(identity("token-foreign")).expect("start profile");
    let runtime = session.runtime();
    let foreign = Runtime::new();
    let foreign_token = foreign.causal_parent();
    assert_ne!(foreign_token.context_id(), runtime.context_id());

    drop(span_with_parent(foreign_token, Stage::BackendDispatch));

    let (records, dropped) = runtime.take_session_span_records();
    assert_eq!(dropped, 0);
    assert_eq!(records.len(), 1);
    assert_eq!(parent_id(&records[0].parent_span_id), None);
    assert!(foreign.take_session_span_records().0.is_empty());
    let _ = session.finish(RunState::Completed);
}

/// A root token (captured outside any span) must link the attached span into
/// the originating runtime while leaving it parentless.
#[test]
fn root_token_attaches_span_to_originating_runtime_as_root() {
    let session = Session::start(identity("token-root")).expect("start profile");
    let runtime = session.runtime();
    let token = current_causal_parent().expect("runtime captures token");
    assert!(token.is_root());

    let worker_runtime = runtime.clone();
    std::thread::spawn(move || {
        worker_runtime.scope(|| {
            drop(span_with_parent(token, Stage::Reporting));
        });
    })
    .join()
    .expect("worker completes");

    let (records, dropped) = runtime.take_session_span_records();
    assert_eq!(dropped, 0);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].metric_id, MetricId::Reporting);
    assert_eq!(parent_id(&records[0].parent_span_id), None);
    let _ = session.finish(RunState::Completed);
}

/// An instrumented future spawned onto another thread with an explicit token
/// must keep the full causal chain: remote parent, async span, and inner span,
/// including exclusive-time subtraction across the boundary.
#[test]
fn instrumented_future_with_token_preserves_chain_across_spawn() {
    let session = Session::start(identity("token-async")).expect("start profile");
    let runtime = session.runtime();
    let outer = span(Stage::SourceAcquire);
    let token = current_causal_parent().expect("runtime captures token");

    let worker_runtime = runtime.clone();
    std::thread::spawn(move || {
        worker_runtime.scope(|| {
            block_on(instrument_future_with_parent(
                token,
                Stage::Preprocess,
                async {
                    YieldOnce(true).await;
                    drop(span(Stage::Decode));
                },
            ));
        });
    })
    .join()
    .expect("worker completes");
    drop(outer);

    let (records, dropped) = runtime.take_session_span_records();
    assert_eq!(dropped, 0);
    assert_eq!(records.len(), 3);
    let parent = records
        .iter()
        .find(|record| record.metric_id == MetricId::SourceAcquire)
        .expect("outer span");
    let async_span = records
        .iter()
        .find(|record| record.metric_id == MetricId::Preprocess)
        .expect("async span");
    let leaf = records
        .iter()
        .find(|record| record.metric_id == MetricId::Decode)
        .expect("leaf span");
    assert_eq!(parent_id(&async_span.parent_span_id), Some(parent.span_id));
    assert_eq!(parent_id(&leaf.parent_span_id), Some(async_span.span_id));
    assert_eq!(
        parent.exclusive_ns,
        parent.inclusive_ns - async_span.inclusive_ns
    );
    assert_eq!(
        async_span.exclusive_ns,
        async_span.inclusive_ns - leaf.inclusive_ns
    );
    assert_ne!(parent.thread_id, async_span.thread_id);
    let _ = session.finish(RunState::Completed);
}

/// Without any runtime the token API must stay a safe no-op instead of
/// manufacturing a context.
#[test]
fn token_capture_without_runtime_is_none() {
    assert!(current_causal_parent().is_none());
}
