#[cfg(not(feature = "entropy"))]
#[test]
fn detector_entropy_policy_requires_the_entropy_feature_before_matcher_construction() {
    let detectors =
        keyhog_core::load_embedded_detectors_or_fail().expect("embedded detectors must load");
    let error = match keyhog_scanner::CompiledScanner::compile_with_gpu_policy(
        detectors,
        keyhog_scanner::GpuInitPolicy::ForceDisabled,
    ) {
        Ok(_) => panic!("a build without entropy accepted detector-owned entropy policy"),
        Err(error) => error,
    };

    let keyhog_scanner::ScanError::Config(detail) = error else {
        panic!("expected a configuration error, got {error}");
    };
    assert!(
        detail.contains("without the `entropy` feature")
            && detail.contains("generic-api-key")
            && detail.contains("generic-keyword-secret")
            && detail.contains("generic-password")
            && detail.contains("generic-secret")
            && detail.contains("BPE policy")
            && detail.contains("--features entropy"),
        "the error must name the unavailable mechanism, affected detectors, and fix: {detail}"
    );
}
