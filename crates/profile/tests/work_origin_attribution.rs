//! Causal work origins generalizing the binary decoded attribution.

use keyhog_profile::{
    instrument_future, set_attribution, set_work_origin, span, Attribution, Evidence, EvidenceGap,
    RunIdentity, RunState, Session, SpanRecordV2, Stage, WorkOrigin,
};
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

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

/// Every work origin set on the thread must be recorded verbatim on the span
/// so downstream analysis can split root, decoded, derived, and retried work.
#[test]
fn spans_record_exact_work_origin() {
    let session = session("origin-on-spans");
    let runtime = session.runtime();
    drop(span(Stage::SourceRead));
    assert_eq!(set_work_origin(WorkOrigin::Retried), WorkOrigin::Root);
    drop(span(Stage::Phase2AnchoredVerify));
    assert_eq!(set_work_origin(WorkOrigin::Derived), WorkOrigin::Retried);
    drop(span(Stage::Decode));
    set_work_origin(WorkOrigin::Root);

    let (spans, dropped) = runtime.take_session_span_records();
    assert_eq!(dropped, 0);
    assert_eq!(spans.len(), 3);
    let origin_of = |stage: Stage| {
        spans
            .iter()
            .find(|record| record.metric_id == stage.metric_id())
            .expect("span for stage")
            .work_origin
    };
    assert_eq!(origin_of(Stage::SourceRead), WorkOrigin::Root);
    assert_eq!(origin_of(Stage::Phase2AnchoredVerify), WorkOrigin::Retried);
    assert_eq!(origin_of(Stage::Decode), WorkOrigin::Derived);
    let _ = session.finish(RunState::Completed);
}

/// The legacy set_attribution API must keep working, mapping onto the decoded
/// origin, and must project any attributed origin back to Decoded.
#[test]
fn legacy_attribution_api_maps_onto_work_origin() {
    let session = session("legacy-attribution");
    let runtime = session.runtime();
    set_work_origin(WorkOrigin::Retried);
    // Legacy projection: any attributed (non-root) origin reads as Decoded.
    assert_eq!(set_attribution(Attribution::Decoded), Attribution::Decoded);
    drop(span(Stage::Decode));
    assert_eq!(set_attribution(Attribution::Root), Attribution::Decoded);
    drop(span(Stage::SourceRead));

    let (spans, _) = runtime.take_session_span_records();
    assert_eq!(spans.len(), 2);
    let decode = spans
        .iter()
        .find(|record| record.metric_id == Stage::Decode.metric_id())
        .expect("decode span");
    assert_eq!(decode.work_origin, WorkOrigin::Decoded);
    let read = spans
        .iter()
        .find(|record| record.metric_id == Stage::SourceRead.metric_id())
        .expect("read span");
    assert_eq!(read.work_origin, WorkOrigin::Root);
    let _ = session.finish(RunState::Completed);
}

/// Decoded, derived, and retried origins must all be captured on the span records,
/// while stage attributed_ns carries exclusive self-time (Row 109).
#[test]
fn non_root_origins_count_as_attributed_work() {
    let session = session("origin-attribution-totals");
    let runtime = session.runtime();
    for origin in [
        WorkOrigin::Decoded,
        WorkOrigin::Derived,
        WorkOrigin::Retried,
    ] {
        set_work_origin(origin);
        drop(span(Stage::GenericDetection));
    }
    set_work_origin(WorkOrigin::Root);
    drop(span(Stage::GenericDetection));

    let (spans, _) = runtime.take_session_span_records();
    assert_eq!(spans.len(), 4);
    assert_eq!(spans[0].work_origin, WorkOrigin::Decoded);
    assert_eq!(spans[1].work_origin, WorkOrigin::Derived);
    assert_eq!(spans[2].work_origin, WorkOrigin::Retried);
    assert_eq!(spans[3].work_origin, WorkOrigin::Root);

    let profile = session.finish(RunState::Completed);
    let stage = profile
        .stages
        .iter()
        .find(|measurement| measurement.stage == Stage::GenericDetection)
        .expect("generic detection measurement");
    assert_eq!(stage.calls, 4);
    assert!(stage.attributed_ns > 0);
    assert!(stage.attributed_ns <= stage.elapsed_ns);
}

/// The work origin must propagate through instrument_future onto a worker
/// thread, exactly like the runtime and causal parent do.
#[test]
fn work_origin_propagates_across_spawned_future() {
    let session = session("origin-across-spawn");
    let runtime = session.runtime();
    set_work_origin(WorkOrigin::Retried);
    let task = instrument_future(Stage::LiveVerification, async {
        drop(span(Stage::GenericDetection));
    });
    set_work_origin(WorkOrigin::Root);
    std::thread::spawn(move || block_on(task))
        .join()
        .expect("worker completes");

    let (spans, _) = runtime.take_session_span_records();
    assert_eq!(spans.len(), 2);
    assert!(spans
        .iter()
        .all(|record| record.work_origin == WorkOrigin::Retried));
    let _ = session.finish(RunState::Completed);
}

/// Span records serialized before work_origin existed must decode with the
/// root default, and current records must round-trip with explicit origins.
#[test]
fn legacy_span_json_decodes_root_and_new_origins_round_trip() {
    let session = session("origin-serde");
    let runtime = session.runtime();
    set_work_origin(WorkOrigin::Retried);
    drop(span(Stage::Suppression));
    set_work_origin(WorkOrigin::Root);
    let (spans, _) = runtime.take_session_span_records();
    assert_eq!(spans.len(), 1);

    let mut json = serde_json::to_value(&spans[0]).expect("serialize span");
    assert_eq!(json["work_origin"], serde_json::json!("retried"));
    let object = json.as_object_mut().expect("span object");
    object.remove("work_origin");
    object.remove("worker_id");
    let decoded: SpanRecordV2 = serde_json::from_value(json).expect("decode legacy span");
    assert_eq!(decoded.work_origin, WorkOrigin::Root);
    assert_eq!(
        decoded.worker_id,
        Evidence::unavailable(EvidenceGap::LegacyV1NotRecorded)
    );

    let round_trip: SpanRecordV2 =
        serde_json::from_value(serde_json::to_value(&spans[0]).expect("serialize span again"))
            .expect("round-trip span");
    assert_eq!(round_trip, spans[0]);
    let _ = session.finish(RunState::Completed);
}
