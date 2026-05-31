use keyhog::orchestrator::backend_requires_legacy_gpu_pipeline_for_test;
use keyhog_scanner::hw_probe::ScanBackend;

#[test]
fn auto_filesystem_backend_does_not_require_legacy_gpu_pipeline() {
    assert!(
        !backend_requires_legacy_gpu_pipeline_for_test(None),
        "auto/default filesystem scans should stay eligible for the fused pipeline"
    );
}

#[test]
fn explicit_gpu_backends_keep_legacy_gpu_pipeline() {
    assert!(backend_requires_legacy_gpu_pipeline_for_test(Some(
        ScanBackend::Gpu
    )));
    assert!(backend_requires_legacy_gpu_pipeline_for_test(Some(
        ScanBackend::MegaScan
    )));
}

#[test]
fn explicit_cpu_backends_stay_fused_eligible() {
    assert!(!backend_requires_legacy_gpu_pipeline_for_test(Some(
        ScanBackend::SimdCpu
    )));
    assert!(!backend_requires_legacy_gpu_pipeline_for_test(Some(
        ScanBackend::CpuFallback
    )));
}
