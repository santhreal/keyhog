use keyhog_profile::{
    record_event, record_sampled_event, EventId, RunIdentity, RunState, SamplingPolicy, Session,
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

/// A bounded policy must retain its exact deterministic prefix and stride, then stop at the cap.
#[test]
fn bounded_policy_retains_exact_prefix_stride_and_maximum() {
    let session = session("bounded-sequence");
    let runtime = session.runtime();
    let policy = SamplingPolicy::bounded(2, 3, 5);
    let retained: Vec<_> = (0..21_u64)
        .filter(|value| record_sampled_event(EventId::DetailedDiagnostic, *value, policy))
        .collect();
    assert_eq!(retained, [0, 1, 2, 5, 8]);
    let (events, annotations, event_loss) = runtime.take_session_typed_events();
    assert_eq!(events.len(), 5);
    assert_eq!(
        events.iter().map(|event| event.value).collect::<Vec<_>>(),
        retained
    );
    assert!(events
        .iter()
        .all(|event| event.event_id == EventId::DetailedDiagnostic));
    assert!(annotations.is_empty());
    assert_eq!(event_loss.capacity_drops(), 0);
    assert_eq!(event_loss.sampled_out_events, 16);
    let _ = session.finish(RunState::Completed);
}

/// A zero retention bound must retain nothing and must count every observation as sampled out.
#[test]
fn zero_maximum_samples_out_every_observation() {
    let session = session("zero-maximum");
    let runtime = session.runtime();
    let policy = SamplingPolicy::bounded(100, 0, 0);
    for value in 0..32 {
        assert!(!record_sampled_event(
            EventId::DetailedDiagnostic,
            value,
            policy
        ));
    }
    let (events, annotations, event_loss) = runtime.take_session_typed_events();
    assert!(events.is_empty());
    assert!(annotations.is_empty());
    assert_eq!(event_loss.capacity_drops(), 0);
    assert_eq!(event_loss.sampled_out_events, 32);
    let _ = session.finish(RunState::Completed);
}

/// Independent event IDs must have independent observation and retention budgets.
#[test]
fn event_identifiers_do_not_share_sampling_budget() {
    let session = session("independent-identifiers");
    let runtime = session.runtime();
    let policy = SamplingPolicy::bounded(1, 10, 1);
    assert!(record_sampled_event(
        EventId::DetailedDiagnostic,
        11,
        policy
    ));
    assert!(!record_sampled_event(
        EventId::DetailedDiagnostic,
        12,
        policy
    ));
    assert!(record_sampled_event(EventId::CoverageGap, 21, policy));
    assert!(!record_sampled_event(EventId::CoverageGap, 22, policy));
    let (events, _, event_loss) = runtime.take_session_typed_events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_id, EventId::DetailedDiagnostic);
    assert_eq!(events[1].event_id, EventId::CoverageGap);
    assert_eq!(event_loss.capacity_drops(), 0);
    assert_eq!(event_loss.sampled_out_events, 2);
    let _ = session.finish(RunState::Completed);
}

/// Concurrent producers must never exceed the policy cap and must account for every rejected event.
#[test]
fn concurrent_sampling_enforces_one_global_per_event_cap() {
    let session = session("concurrent-sampling");
    let runtime = session.runtime();
    let policy = SamplingPolicy::bounded(1_000, 1, 100);
    let workers: Vec<_> = (0..8)
        .map(|worker| {
            let runtime = runtime.clone();
            std::thread::spawn(move || {
                runtime.scope(|| {
                    for offset in 0..125 {
                        let value = worker * 125 + offset;
                        record_sampled_event(EventId::DetailedDiagnostic, value, policy);
                    }
                });
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("worker completes");
    }
    let (events, annotations, event_loss) = runtime.take_session_typed_events();
    assert_eq!(events.len(), 100);
    assert!(annotations.is_empty());
    assert_eq!(event_loss.capacity_drops(), 0);
    assert_eq!(event_loss.sampled_out_events, 900);
    let _ = session.finish(RunState::Completed);
}

/// Unsampled point events must bypass detail sampling without consuming its retained budget.
#[test]
fn ordinary_events_do_not_consume_sampled_event_budget() {
    let session = session("ordinary-events");
    let runtime = session.runtime();
    let policy = SamplingPolicy::bounded(1, 1, 1);
    record_event(EventId::DetailedDiagnostic, 1);
    assert!(record_sampled_event(EventId::DetailedDiagnostic, 2, policy));
    assert!(!record_sampled_event(
        EventId::DetailedDiagnostic,
        3,
        policy
    ));
    let (events, _, event_loss) = runtime.take_session_typed_events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].value, 1);
    assert_eq!(events[1].value, 2);
    assert_eq!(event_loss.capacity_drops(), 0);
    assert_eq!(event_loss.sampled_out_events, 1);
    let _ = session.finish(RunState::Completed);
}

/// Sampling without an active runtime must return false and leave the next session pristine.
#[test]
fn sampled_event_without_runtime_is_not_reported_as_retained() {
    let policy = SamplingPolicy::bounded(1, 1, 1);
    assert!(!record_sampled_event(
        EventId::DetailedDiagnostic,
        1,
        policy
    ));
    let session = session("pristine");
    let runtime = session.runtime();
    let (events, annotations, event_loss) = runtime.take_session_typed_events();
    assert!(events.is_empty());
    assert!(annotations.is_empty());
    assert_eq!(
        (event_loss.capacity_drops(), event_loss.sampled_out_events),
        (0, 0)
    );
    let _ = session.finish(RunState::Completed);
}
