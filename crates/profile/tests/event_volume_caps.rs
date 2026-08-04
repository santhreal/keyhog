use keyhog_profile::{
    record_annotation, record_event, record_sampled_event, AnnotationId, EventId, RunIdentity,
    RunState, SamplingPolicy, Session, MAX_ANNOTATIONS, MAX_POINT_EVENTS,
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

/// Point-event retention must stop at its fixed bound and report every discarded record exactly.
#[test]
fn point_event_capacity_reports_exact_loss() {
    let session = session("point-cap");
    let runtime = session.runtime();
    for value in 0..u64::try_from(MAX_POINT_EVENTS + 17).expect("event count fits u64") {
        record_event(EventId::CoverageGap, value);
    }

    let (events, annotations, loss) = runtime.take_session_typed_events();
    assert_eq!(events.len(), MAX_POINT_EVENTS);
    assert!(annotations.is_empty());
    assert_eq!(loss.point_events, 17);
    assert_eq!(loss.annotations, 0);
    assert_eq!(loss.sampled_out_events, 0);
    assert_eq!(loss.capacity_drops(), 17);
    assert_eq!(events.first().expect("first event").sequence, 0);
    assert_eq!(events.last().expect("last event").sequence, 16_383);
    let _ = session.finish(RunState::Completed);
}

/// Annotation loss must remain distinct from point-event loss while both streams stay usable.
#[test]
fn annotation_capacity_has_independent_loss_accounting() {
    let session = session("annotation-cap");
    let runtime = session.runtime();
    for value in 0..u64::try_from(MAX_ANNOTATIONS + 9).expect("annotation count fits u64") {
        record_annotation(AnnotationId::QueueDepth, value);
    }
    record_event(EventId::Interrupted, 130);

    let (events, annotations, loss) = runtime.take_session_typed_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, EventId::Interrupted);
    assert_eq!(annotations.len(), MAX_ANNOTATIONS);
    assert_eq!(loss.point_events, 0);
    assert_eq!(loss.annotations, 9);
    assert_eq!(loss.sampled_out_events, 0);
    assert_eq!(loss.capacity_drops(), 9);
    let _ = session.finish(RunState::Completed);
}

/// Sampled recording must return false when capacity rejects an otherwise selected observation.
#[test]
fn sampled_event_result_reports_actual_retention_at_capacity() {
    let session = session("sample-cap");
    let runtime = session.runtime();
    let policy = SamplingPolicy::bounded(
        u64::try_from(MAX_POINT_EVENTS + 3).expect("event count fits u64"),
        1,
        u64::try_from(MAX_POINT_EVENTS + 3).expect("event count fits u64"),
    );
    let mut retained = 0_usize;
    for value in 0..u64::try_from(MAX_POINT_EVENTS + 3).expect("event count fits u64") {
        retained += usize::from(record_sampled_event(
            EventId::DetailedDiagnostic,
            value,
            policy,
        ));
    }

    let (events, annotations, loss) = runtime.take_session_typed_events();
    assert_eq!(retained, MAX_POINT_EVENTS);
    assert_eq!(events.len(), MAX_POINT_EVENTS);
    assert!(annotations.is_empty());
    assert_eq!(loss.point_events, 3);
    assert_eq!(loss.annotations, 0);
    assert_eq!(loss.sampled_out_events, 0);
    let _ = session.finish(RunState::Completed);
}

/// Concurrent producers must not race past the bound or lose overflow accounting increments.
#[test]
fn concurrent_point_event_overflow_is_bounded_and_lossless() {
    let session = session("concurrent-cap");
    let runtime = session.runtime();
    let workers: Vec<_> = (0..4_u64)
        .map(|worker| {
            let runtime = runtime.clone();
            std::thread::spawn(move || {
                runtime.scope(|| {
                    for index in 0..4_200_u64 {
                        record_event(EventId::CoverageGap, worker * 4_200 + index);
                    }
                });
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("event producer completes");
    }

    let (events, annotations, loss) = runtime.take_session_typed_events();
    assert_eq!(events.len(), MAX_POINT_EVENTS);
    assert!(annotations.is_empty());
    assert_eq!(loss.point_events, 16_800 - MAX_POINT_EVENTS as u64);
    assert_eq!(loss.annotations, 0);
    assert_eq!(loss.sampled_out_events, 0);
    let _ = session.finish(RunState::Completed);
}

/// Draining must release retained capacity and reset loss counters for the next bounded interval.
#[test]
fn destructive_drain_resets_capacity_and_loss_interval() {
    let session = session("drain-reset");
    let runtime = session.runtime();
    for value in 0..u64::try_from(MAX_POINT_EVENTS + 1).expect("event count fits u64") {
        record_event(EventId::CoverageGap, value);
    }
    let (first_events, _, first_loss) = runtime.take_session_typed_events();
    assert_eq!(first_events.len(), MAX_POINT_EVENTS);
    assert_eq!(first_loss.point_events, 1);

    record_event(EventId::CoverageGap, 99);
    let (second_events, second_annotations, second_loss) = runtime.take_session_typed_events();
    assert_eq!(second_events.len(), 1);
    assert_eq!(second_events[0].value, 99);
    assert!(second_annotations.is_empty());
    assert_eq!(second_loss.capacity_drops(), 0);
    assert_eq!(second_loss.sampled_out_events, 0);
    let _ = session.finish(RunState::Completed);
}
