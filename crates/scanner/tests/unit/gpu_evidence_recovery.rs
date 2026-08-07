//! Recovery evidence contracts: the fault -> residual -> retry -> recovery
//! sequences the dispatch code records on degraded routes keep exact counts
//! and event ordering semantics through the profile runtime.

use crate::gpu::evidence;

/// The canonical degradation sequence (fault, residual CPU batch) records
/// exactly one fault event with its kind and one residual batch per call.
#[test]
fn degradation_sequence_records_fault_and_residual_exactly() {
    let runtime = keyhog_profile::Runtime::new();
    runtime.scope(|| {
        evidence::record_fault(evidence::BACKEND_WGPU, evidence::fault::DISPATCH);
        evidence::record_residual_batch();
        evidence::record_fault(evidence::BACKEND_WGPU, evidence::fault::DISPATCH);
        evidence::record_residual_batch();
    });
    let metrics = runtime.take_session_typed_metrics();
    let value = |id: keyhog_profile::MetricId| -> u64 {
        metrics
            .iter()
            .find(|metric| metric.metric_id == id)
            .map_or(0, |metric| metric.value)
    };
    assert_eq!(value(keyhog_profile::CounterId::GpuFaults.metric_id()), 2);
    assert_eq!(
        value(keyhog_profile::CounterId::GpuResidualBatches.metric_id()),
        2
    );
    let (events, _, _) = runtime.take_session_typed_events();
    let kinds: Vec<u64> = events
        .iter()
        .filter(|event| event.event_id == keyhog_profile::EventId::GpuFault)
        .map(|event| event.value)
        .collect();
    assert_eq!(
        kinds,
        vec![evidence::fault::DISPATCH, evidence::fault::DISPATCH]
    );
}

/// The recovery sequence (retry attempts then recovery) keeps attempt indexes
/// and emits the BackendRecovered event exactly once per recovery.
#[test]
fn recovery_sequence_records_attempts_and_recovery_event() {
    let runtime = keyhog_profile::Runtime::new();
    runtime.scope(|| {
        evidence::record_retry(1);
        evidence::record_retry(2);
        evidence::record_recovery(evidence::BACKEND_WGPU);
    });
    let metrics = runtime.take_session_typed_metrics();
    let value = |id: keyhog_profile::MetricId| -> u64 {
        metrics
            .iter()
            .find(|metric| metric.metric_id == id)
            .map_or(0, |metric| metric.value)
    };
    assert_eq!(value(keyhog_profile::CounterId::GpuRetries.metric_id()), 2);
    assert_eq!(
        value(keyhog_profile::CounterId::GpuRecoveries.metric_id()),
        1
    );
    let (events, annotations, _) = runtime.take_session_typed_events();
    let attempts: Vec<u64> = annotations
        .iter()
        .filter(|a| a.annotation_id == keyhog_profile::AnnotationId::RetryAttempt)
        .map(|a| a.value)
        .collect();
    assert_eq!(attempts, vec![1, 2]);
    let recoveries: Vec<u64> = events
        .iter()
        .filter(|event| event.event_id == keyhog_profile::EventId::BackendRecovered)
        .map(|event| event.value)
        .collect();
    assert_eq!(recoveries, vec![evidence::BACKEND_WGPU]);
}

/// The dispatch fault code remains stable for profile consumers.
#[test]
fn fault_codes_are_stable() {
    assert_eq!(evidence::fault::DISPATCH, 1);
}
