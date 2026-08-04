use keyhog_profile::{
    add_counter, add_input_bytes, add_input_units, record_annotation, record_batch_route,
    record_event, set_gauge, AnnotationId, CounterId, EventId, GaugeId, MetricId, MetricKind,
    RunIdentity, RunState, Session,
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

/// Existing input APIs must feed the typed counter registry without changing aggregate input truth.
#[test]
fn input_accounting_materializes_typed_counters_from_one_recording_call() {
    let session = session("input-counters");
    let runtime = session.runtime();
    add_input_bytes(41);
    add_input_bytes(1);
    add_input_units(2);
    let metrics = runtime.take_session_typed_metrics();
    assert_eq!(metrics.len(), 2);
    assert_eq!(metrics[0].metric_id, MetricId::InputBytes);
    assert_eq!(metrics[0].kind, MetricKind::Counter);
    assert_eq!(metrics[0].value, 42);
    assert_eq!(metrics[1].metric_id, MetricId::InputUnits);
    assert_eq!(metrics[1].kind, MetricKind::Counter);
    assert_eq!(metrics[1].value, 2);
    let profile = session.finish(RunState::Completed);
    assert_eq!(profile.input_bytes, 42);
    assert_eq!(profile.input_units, 2);
}

/// Counter addition and zero-valued gauges must preserve their distinct metric semantics.
#[test]
fn typed_counter_and_gauge_records_retain_exact_values_and_kinds() {
    let session = session("counter-gauge");
    let runtime = session.runtime();
    add_counter(CounterId::ProcessCpuTime, 7);
    add_counter(CounterId::ProcessCpuTime, 5);
    set_gauge(GaugeId::ResidentMemory, 4096);
    set_gauge(GaugeId::ProcessThreads, 0);
    let metrics = runtime.take_session_typed_metrics();
    assert_eq!(metrics.len(), 3);
    assert_eq!(metrics[0].metric_id, MetricId::ProcessCpuTime);
    assert_eq!(metrics[0].kind, MetricKind::Counter);
    assert_eq!(metrics[0].value, 12);
    assert_eq!(metrics[1].metric_id, MetricId::ResidentMemory);
    assert_eq!(metrics[1].kind, MetricKind::Gauge);
    assert_eq!(metrics[1].value, 4096);
    assert_eq!(metrics[2].metric_id, MetricId::ProcessThreads);
    assert_eq!(metrics[2].kind, MetricKind::Gauge);
    assert_eq!(metrics[2].value, 0);
    let _ = session.finish(RunState::Completed);
}

/// Events and annotations must share monotonic ordering while retaining typed IDs and numeric values.
#[test]
fn point_events_and_annotations_share_one_causal_sequence() {
    let session = session("events-annotations");
    let runtime = session.runtime();
    record_event(EventId::CoverageGap, 3);
    record_annotation(AnnotationId::QueueDepth, 17);
    record_event(EventId::Interrupted, 130);
    let (events, annotations, event_loss) = runtime.take_session_typed_events();
    assert_eq!(
        (event_loss.capacity_drops(), event_loss.sampled_out_events),
        (0, 0)
    );
    assert_eq!(events.len(), 2);
    assert_eq!(annotations.len(), 1);
    assert_eq!(events[0].sequence, 0);
    assert_eq!(events[0].event_id, EventId::CoverageGap);
    assert_eq!(events[0].value, 3);
    assert_eq!(annotations[0].sequence, 1);
    assert_eq!(annotations[0].annotation_id, AnnotationId::QueueDepth);
    assert_eq!(annotations[0].value, 17);
    assert_eq!(events[1].sequence, 2);
    assert_eq!(events[1].event_id, EventId::Interrupted);
    assert_eq!(events[1].value, 130);
    assert_eq!(events[0].thread_id, annotations[0].thread_id);
    assert!(events[0].elapsed_ns <= annotations[0].elapsed_ns);
    assert!(annotations[0].elapsed_ns <= events[1].elapsed_ns);
    let _ = session.finish(RunState::Completed);
}

/// Backend route recording must emit completion and recovery events from the production API.
#[test]
fn recovered_batch_route_emits_typed_completion_and_recovery_events() {
    let session = session("route-events");
    let runtime = session.runtime();
    record_batch_route("workload", "auto", "gpu", "cpu-simd", Some("gpu"));
    let (events, annotations, event_loss) = runtime.take_session_typed_events();
    assert_eq!(
        (event_loss.capacity_drops(), event_loss.sampled_out_events),
        (0, 0)
    );
    assert!(annotations.is_empty());
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_id, EventId::BackendBatchCompleted);
    assert_eq!(events[0].value, 0);
    assert_eq!(events[1].event_id, EventId::BackendRecovered);
    assert_eq!(events[1].value, 0);
    let routes = runtime.take_session_batch_routes();
    assert_eq!(routes.len(), 1);
    let _ = session.finish(RunState::Completed);
}

/// Typed recording outside an active runtime must remain a safe no-op instead of creating global state.
#[test]
fn typed_recording_without_context_is_a_noop() {
    add_counter(CounterId::InputBytes, 99);
    set_gauge(GaugeId::VirtualMemory, 99);
    record_event(EventId::CoverageGap, 99);
    record_annotation(AnnotationId::RetryAttempt, 99);
    let session = session("fresh-after-noop");
    let runtime = session.runtime();
    assert!(runtime.take_session_typed_metrics().is_empty());
    let (events, annotations, event_loss) = runtime.take_session_typed_events();
    assert!(events.is_empty());
    assert!(annotations.is_empty());
    assert_eq!(
        (event_loss.capacity_drops(), event_loss.sampled_out_events),
        (0, 0)
    );
    let _ = session.finish(RunState::Completed);
}

/// Concurrent counter increments must be lossless and gauge replacement must remain a valid observed value.
#[test]
fn concurrent_typed_metrics_merge_without_counter_loss() {
    let session = session("concurrent-typed");
    let runtime = session.runtime();
    let workers: Vec<_> = (0..8_u64)
        .map(|worker_index| {
            let runtime = runtime.clone();
            std::thread::spawn(move || {
                runtime.scope(|| {
                    for _ in 0..100 {
                        add_counter(CounterId::InputUnits, 1);
                    }
                    set_gauge(GaugeId::ProcessThreads, worker_index);
                });
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("worker completes");
    }
    let metrics = runtime.take_session_typed_metrics();
    let counter = metrics
        .iter()
        .find(|metric| metric.metric_id == MetricId::InputUnits)
        .expect("input-unit counter");
    assert_eq!(counter.value, 800);
    let gauge = metrics
        .iter()
        .find(|metric| metric.metric_id == MetricId::ProcessThreads)
        .expect("thread gauge");
    assert!(gauge.value < 8);
    let _ = session.finish(RunState::Completed);
}
