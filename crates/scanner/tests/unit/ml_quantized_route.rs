use crate::ml_scorer::{score_input_batch, score_input_batch_quantized_cpu, MlScoreInput};

/// WHY: authenticated CPU peers and GPU dispatches must share one fixed-point
/// oracle while explicitly CPU-owned candidates retain the float policy.
#[test]
fn quantized_cpu_route_matches_fixed_point_oracle_and_cpu_owned_policy() {
    let config = crate::types::ScannerConfig::default();
    let inputs = [
        (
            "sk-proj-aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0zA3cD6eF9h",
            "OPENAI_API_KEY=",
        ),
        ("", "API_KEY="),
    ];
    let scores = score_input_batch_quantized_cpu(&inputs, &config).expect("quantized CPU scoring");
    let row = crate::confidence::quantized::QuantizedFeatureRow::from_float(
        &inputs[0].ml_features(&config),
    )
    .expect("representable feature row");
    assert_eq!(
        scores[0],
        crate::confidence::quantized::model()
            .expect("embedded quantized model")
            .score(&row)
            .as_f64()
    );
    assert_eq!(
        scores[1],
        score_input_batch(&inputs[1..], &config)[0],
        "CPU-owned candidates retain the established float policy"
    );
}

/// WHY: a diagnostic GPU route compiled from a validated live detector corpus
/// has no execution pack to authenticate, but must still use the build-validated
/// embedded quantized model instead of leaving every ML-enabled batch unscanned.
#[cfg(feature = "gpu")]
#[test]
fn direct_gpu_route_authenticates_embedded_quantized_artifact() {
    let scanner = crate::CompiledScanner::compile_for_backend(
        Vec::new(),
        crate::hw_probe::ScanBackend::GpuWgpu,
    )
    .expect("direct GPU scanner compiles");
    assert!(
        scanner.quantized_confidence_authenticated,
        "validated live detector compiles authenticate the embedded quantized model"
    );
}

/// WHY: a GPU-selected execution pack without the model binding must not
/// silently run the floating-point CPU scorer and claim the selected route.
#[cfg(feature = "gpu")]
#[test]
fn selected_gpu_route_rejects_missing_quantized_artifact_authentication() {
    let mut scanner = crate::CompiledScanner::compile(Vec::new()).expect("empty scanner compiles");
    scanner.quantized_confidence_authenticated = false;
    let error = scanner
        .score_pending_batch_for_test(&[], crate::hw_probe::ScanBackend::GpuWgpu)
        .expect_err("unauthenticated GPU confidence route must fail closed");
    assert!(matches!(
        error,
        crate::ScanError::Gpu(reason)
            if reason.contains("lacks an authenticated quantized-confidence artifact binding")
    ));
}
