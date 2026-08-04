//! Contracts for the normalized accelerator evidence channel: typed metrics
//! record through the profile runtime, stay silent without one, and the pure
//! normalization helpers keep exact semantics.

use super::*;

/// Every recorder must emit its exact typed metric under an active runtime.
#[test]
fn dispatch_evidence_records_exact_typed_metrics() {
    let runtime = keyhog_profile::Runtime::new();
    runtime.scope(|| {
        record_dispatch_submitted();
        record_upload(4096, Some(100));
        record_readback(2048, Some(50));
        record_submit_to_complete(900);
        record_kernel(700);
        record_queue_wait(200);
        record_compile(321);
        record_overlap(150);
        record_residual_batch();
    });
    let metrics = runtime.take_session_typed_metrics();
    let value = |id: MetricId| {
        metrics
            .iter()
            .find(|metric| metric.metric_id == id)
            .unwrap_or_else(|| panic!("missing metric {id:?}"))
            .value
    };
    assert_eq!(value(CounterId::GpuDispatchCalls.metric_id()), 1);
    assert_eq!(value(CounterId::GpuUploadBytes.metric_id()), 4096);
    assert_eq!(value(CounterId::GpuUploadNs.metric_id()), 100);
    assert_eq!(value(CounterId::GpuReadbackBytes.metric_id()), 2048);
    assert_eq!(value(CounterId::GpuReadbackNs.metric_id()), 50);
    assert_eq!(value(CounterId::GpuSubmitToCompleteNs.metric_id()), 900);
    assert_eq!(value(CounterId::GpuKernelNs.metric_id()), 700);
    assert_eq!(value(CounterId::GpuQueueWaitNs.metric_id()), 200);
    assert_eq!(value(CounterId::GpuCompileNs.metric_id()), 321);
    assert_eq!(value(CounterId::GpuCompileCalls.metric_id()), 1);
    assert_eq!(value(CounterId::GpuPipelineCacheMisses.metric_id()), 1);
    assert_eq!(value(CounterId::GpuOverlapNs.metric_id()), 150);
    assert_eq!(value(CounterId::GpuResidualBatches.metric_id()), 1);
}

/// Recording without an active runtime must stay a no-op so CPU-only scans emit nothing.
#[test]
fn evidence_without_runtime_records_nothing() {
    let runtime = keyhog_profile::Runtime::new();
    record_dispatch_submitted();
    record_upload(1, Some(1));
    record_readback(1, Some(1));
    assert!(runtime.take_session_typed_metrics().is_empty());
}

/// Backend code normalization is total and stable for the in-tree backends.
#[test]
fn backend_code_maps_known_backends() {
    assert_eq!(backend_code("cuda"), BACKEND_CUDA);
    assert_eq!(backend_code("metal"), BACKEND_METAL);
    assert_eq!(backend_code("wgpu"), BACKEND_WGPU);
    assert_eq!(backend_code("unknown-future"), BACKEND_WGPU);
}

/// Overlap is the wall-minus-serial fraction and saturates at zero.
#[test]
fn overlap_math_saturates() {
    assert_eq!(overlap_ns(1_000, 700), 300);
    assert_eq!(overlap_ns(700, 1_000), 0);
    assert_eq!(overlap_ns(0, 0), 0);
}

/// Device residency tracks cumulative counters, current gauge, and peak high-water.
#[test]
fn residency_tracks_current_and_peak_exactly() {
    let runtime = keyhog_profile::Runtime::new();
    let (before_resident, before_peak) = resident_bytes_snapshot();
    runtime.scope(|| {
        note_device_alloc(1_000);
        note_device_alloc(500);
        note_device_free(400);
    });
    let metrics = runtime.take_session_typed_metrics();
    let value = |id: MetricId| {
        metrics
            .iter()
            .find(|metric| metric.metric_id == id)
            .unwrap_or_else(|| panic!("missing metric {id:?}"))
            .value
    };
    assert_eq!(value(CounterId::GpuAllocBytes.metric_id()), 1_500);
    assert_eq!(value(CounterId::GpuFreeBytes.metric_id()), 400);
    assert_eq!(value(CounterId::GpuAllocCalls.metric_id()), 2);
    assert_eq!(value(GaugeId::GpuResidentBytes.metric_id()), before_resident + 1_100);
    assert_eq!(
        value(GaugeId::GpuPeakResidentBytes.metric_id()),
        (before_resident + 1_500).max(before_peak)
    );
    let (after_resident, _) = resident_bytes_snapshot();
    assert_eq!(after_resident, before_resident + 1_100);
}

/// Fault, retry, and recovery recording uses exact counters and the BackendRecovered event.
#[test]
fn fault_retry_recovery_record_exactly() {
    let runtime = keyhog_profile::Runtime::new();
    runtime.scope(|| {
        record_fault(BACKEND_WGPU, fault::DISPATCH_LAYOUT);
        record_retry(2);
        record_recovery(BACKEND_WGPU);
    });
    let metrics = runtime.take_session_typed_metrics();
    let value = |id: MetricId| {
        metrics
            .iter()
            .find(|metric| metric.metric_id == id)
            .unwrap_or_else(|| panic!("missing metric {id:?}"))
            .value
    };
    assert_eq!(value(CounterId::GpuFaults.metric_id()), 1);
    assert_eq!(value(CounterId::GpuRetries.metric_id()), 1);
    assert_eq!(value(CounterId::GpuRecoveries.metric_id()), 1);
    let (events, _, _) = runtime.take_session_typed_events();
    assert!(events
        .iter()
        .any(|event| event.event_id == EventId::GpuFault && event.value == fault::DISPATCH_LAYOUT));
    assert!(events
        .iter()
        .any(|event| event.event_id == EventId::BackendRecovered && event.value == BACKEND_WGPU));
}

/// Per-runtime identity and capability reports dedup to exactly one emission per runtime.
#[test]
fn identity_and_capability_dedup_per_runtime() {
    let runtime = keyhog_profile::Runtime::new();
    let identity = AdapterIdentity {
        backend_code: BACKEND_WGPU,
        vendor: 0x10de,
        device: 0x2b85,
        is_software: false,
        name: "test-adapter",
        driver: "test-driver",
        driver_info: "test-info",
    };
    runtime.scope(|| {
        record_adapter_identity(&identity);
        record_adapter_identity(&identity);
        report_counter_caps_unsupported(BACKEND_WGPU);
        report_counter_caps_unsupported(BACKEND_WGPU);
    });
    let (events, annotations, _) = runtime.take_session_typed_events();
    let acquired = events
        .iter()
        .filter(|event| event.event_id == EventId::GpuAdapterAcquired)
        .count();
    assert_eq!(acquired, 1);
    let caps: Vec<_> = events
        .iter()
        .filter(|event| event.event_id == EventId::GpuCapabilityUnsupported)
        .collect();
    assert_eq!(caps.len(), 3);
    assert!(annotations
        .iter()
        .any(|annotation| annotation.annotation_id == AnnotationId::GpuAdapterVendor
            && annotation.value == 0x10de));
    assert!(annotations
        .iter()
        .any(|annotation| annotation.annotation_id == AnnotationId::GpuBackendKind
            && annotation.value == BACKEND_WGPU));
}
