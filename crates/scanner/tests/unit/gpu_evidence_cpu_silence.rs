//! CPU-silence contract: probing GPU availability or running with GPU disabled
//! by policy records no accelerator evidence. Evidence belongs to executed GPU
//! dispatches only; probes and policy-disabled paths stay silent.

use super::*;

/// gpu_available() and gpu_probe() under an active runtime record nothing:
/// acquisition-side probing must not leak evidence into CPU-only profiles.
#[test]
fn availability_probe_records_no_gpu_evidence() {
    let runtime = keyhog_profile::Runtime::new();
    runtime.scope(|| {
        let _ = gpu_available();
        let _ = gpu_probe();
    });
    let metrics = runtime.take_session_typed_metrics();
    assert!(
        metrics
            .iter()
            .all(|metric| !metric.metric_id.descriptor().name.starts_with("gpu-")),
        "availability probe recorded unexpected GPU metrics: {metrics:?}"
    );
    let (events, _, _) = runtime.take_session_typed_events();
    assert!(
        events.iter().all(|event| !matches!(
            event.event_id,
            keyhog_profile::EventId::GpuAdapterAcquired
                | keyhog_profile::EventId::GpuFault
                | keyhog_profile::EventId::GpuCapabilityUnsupported
        )),
        "availability probe recorded unexpected GPU events: {events:?}"
    );
}

/// The policy-disabled answer is cheap and evidence-free: asking after a
/// policy disable returns not-available without recording anything.
#[test]
fn policy_disabled_probe_records_no_gpu_evidence() {
    let runtime = keyhog_profile::Runtime::new();
    runtime.scope(|| {
        if gpu_disabled_by_policy() {
            assert!(!gpu_available());
        }
    });
    assert!(runtime
        .take_session_typed_metrics()
        .iter()
        .all(|metric| !metric.metric_id.descriptor().name.starts_with("gpu-")),);
}
