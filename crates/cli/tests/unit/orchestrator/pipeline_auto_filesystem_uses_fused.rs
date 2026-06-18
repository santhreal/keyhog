use keyhog::testing::{CliTestApi as _, API};
use keyhog_scanner::hw_probe::ScanBackend;

#[test]
fn auto_filesystem_backend_does_not_require_coalesced_batch_pipeline() {
    assert!(
        !API.backend_requires_coalesced_batch_pipeline_for_test(None),
        "auto/default filesystem scans should stay eligible for the fused pipeline"
    );
}

#[test]
fn explicit_gpu_backends_keep_coalesced_batch_pipeline() {
    assert!(API.backend_requires_coalesced_batch_pipeline_for_test(Some(ScanBackend::Gpu)));
    assert!(API.backend_requires_coalesced_batch_pipeline_for_test(Some(ScanBackend::MegaScan)));
}

#[test]
fn explicit_cpu_backends_stay_fused_eligible() {
    assert!(!API.backend_requires_coalesced_batch_pipeline_for_test(Some(ScanBackend::SimdCpu)));
    assert!(!API.backend_requires_coalesced_batch_pipeline_for_test(Some(ScanBackend::CpuFallback)));
}
