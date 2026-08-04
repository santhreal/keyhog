//! Dispatch-level accelerator evidence: a real GPU dispatch under an active
//! profile runtime records upload, submit-to-complete, readback, and dispatch
//! evidence through the normalized typed channel. Follows the existing
//! gpu_backend.rs parity conventions (gpu_test_lock, explicit policy failure
//! on acquisition errors).

use super::*;

/// One live MoE dispatch under a profile runtime records exact batch evidence:
/// dispatch count, upload/readback bytes for the probe batch, and timing
/// counters for upload, submit-to-complete, and readback.
#[test]
fn gpu_dispatch_records_batch_evidence_under_profile_runtime() {
    let _gpu_test_guard = crate::testing::gpu_test_lock();
    let gpu_available = match get_gpu() {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(error) => panic!("GPU acquisition policy failure: {error}"),
    };
    if super::super::gpu_disabled_by_policy() || !gpu_available {
        eprintln!("no usable GPU adapter; skipping GPU dispatch evidence regression");
        return;
    }
    let probe = gpu_moe_parity_probe_features();
    assert!(probe.len() >= GPU_BATCH_THRESHOLD);
    let runtime = keyhog_profile::Runtime::new();
    runtime.scope(|| {
        let timeout = Duration::from_millis(30_000);
        let scores = dispatch_moe_batch(&probe, timeout)
            .expect("GPU MoE dispatch returned a typed failure")
            .unwrap_or_else(|| panic!("GPU MoE dispatch returned no result")); // LAW10: test-only proof panic; a missing dispatch is the failure under test
        assert_eq!(scores.len(), probe.len());
    });
    let metrics = runtime.take_session_typed_metrics();
    let value = |id: keyhog_profile::MetricId| -> u64 {
        metrics
            .iter()
            .find(|metric| metric.metric_id == id)
            .map_or(0, |metric| metric.value)
    };
    assert_eq!(
        value(keyhog_profile::CounterId::GpuDispatchCalls.metric_id()),
        1,
        "one dispatch must record exactly one dispatch call"
    );
    let expected_bytes = (probe.len() * INPUT_DIM * std::mem::size_of::<f32>()) as u64
        + std::mem::size_of::<GpuParams>() as u64;
    assert_eq!(
        value(keyhog_profile::CounterId::GpuUploadBytes.metric_id()),
        expected_bytes,
        "upload bytes must equal the feature matrix plus the params uniform"
    );
    let readback_bytes = (probe.len() * std::mem::size_of::<f32>()) as u64;
    assert_eq!(
        value(keyhog_profile::CounterId::GpuReadbackBytes.metric_id()),
        readback_bytes,
        "readback bytes must equal the score vector size"
    );
    assert!(
        value(keyhog_profile::CounterId::GpuSubmitToCompleteNs.metric_id()) > 0,
        "submit-to-complete latency must be measured on a live dispatch"
    );
}

/// A CPU-only scan path on a GPU host must emit no accelerator evidence:
/// recording only happens inside dispatch code, never at acquisition.
#[test]
fn cpu_only_runtime_collects_no_gpu_evidence() {
    let runtime = keyhog_profile::Runtime::new();
    runtime.scope(|| {
        // No dispatch: the runtime sees only ordinary CPU stage work.
        let _span = keyhog_profile::span(keyhog_profile::Stage::Preprocess);
    });
    let metrics = runtime.take_session_typed_metrics();
    assert!(
        metrics
            .iter()
            .all(|metric| !metric.metric_id.descriptor().name.starts_with("gpu-")),
        "CPU-only runtime recorded unexpected GPU metrics: {metrics:?}"
    );
}
