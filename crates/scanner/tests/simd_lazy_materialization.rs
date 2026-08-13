#![cfg(feature = "simd")]

use keyhog_core::{Chunk, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, GpuInitPolicy, ScanBackend, ScannerTuningConfig};

fn scanner(backend: ScanBackend) -> CompiledScanner {
    CompiledScanner::compile_for_backend(
        vec![DetectorSpec {
            id: "simd-lazy-peer".into(),
            name: "SIMD lazy peer".into(),
            service: "test".into(),
            severity: Severity::High,
            patterns: vec![PatternSpec {
                regex: "KHSIMDLAZY_[A-Za-z0-9]{20}".into(),
                ..PatternSpec::default()
            }],
            keywords: vec!["KHSIMDLAZY".into()],
            ..keyhog_scanner::testing::named_detector_fixture_defaults()
        }],
        backend,
    )
    .expect("compile selected scanner plan")
}

#[test]
fn scalar_execution_does_not_materialize_hyperscan_but_selected_simd_does() {
    let scalar_scanner = scanner(ScanBackend::CpuFallback);
    assert!(!scalar_scanner.simd_backend_available());
    assert!(!scalar_scanner.simd_backend_initialized());

    let simd_scanner = scanner(ScanBackend::SimdCpu);
    assert!(simd_scanner.simd_backend_available());
    assert!(!simd_scanner.simd_backend_initialized());

    let chunk = Chunk::from("token=KHSIMDLAZY_A1b2C3d4E5f6G7h8I9j0");
    let scalar = scalar_scanner
        .scan_coalesced_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .expect("scalar lazy-materialization scan should succeed");
    assert_eq!(scalar[0].len(), 1);
    assert!(
        !scalar_scanner.simd_backend_initialized(),
        "a scalar route must not pay Hyperscan initialization"
    );

    assert!(simd_scanner.warm_backend(ScanBackend::SimdCpu));
    assert!(simd_scanner.simd_backend_initialized());
    assert!(simd_scanner
        .simd_initialization_ns()
        .is_some_and(|ns| ns > 0));
    let simd = simd_scanner
        .scan_coalesced_with_backend(&[chunk], ScanBackend::SimdCpu)
        .expect("selected SIMD lazy-materialization scan should succeed");
    assert_eq!(simd, scalar);
}

#[test]
fn selected_simd_without_a_plan_returns_the_exact_typed_error() {
    let scanner = CompiledScanner::compile_for_backend(Vec::new(), ScanBackend::SimdCpu)
        .expect("compile empty SIMD detector corpus");
    let error = scanner
        .scan_coalesced_with_backend_and_admission(
            &[Chunk::from("abc")],
            ScanBackend::SimdCpu,
            None,
        )
        .expect_err("a selected SIMD route without a plan must fail");

    assert!(matches!(error, keyhog_scanner::ScanError::Simd(_)));
    assert!(
        error
            .to_string()
            .contains("detector corpus produced no Hyperscan phase-one plan"),
        "initialization error must preserve the exact missing-plan reason: {error}"
    );
}

#[test]
fn scalar_route_does_not_borrow_the_phase_two_hyperscan_engine() {
    let detectors = vec![
        DetectorSpec {
            id: "phase1-owner".into(),
            name: "Phase-one owner".into(),
            service: "test".into(),
            severity: Severity::High,
            patterns: vec![PatternSpec {
                regex: r"PHASE1_[A-Z0-9]{16}".into(),
                ..PatternSpec::default()
            }],
            keywords: vec!["PHASE1_".into()],
            ..keyhog_scanner::testing::named_detector_fixture_defaults()
        },
        DetectorSpec {
            id: "phase2-owner".into(),
            name: "Phase-two owner".into(),
            service: "test".into(),
            severity: Severity::High,
            patterns: vec![PatternSpec {
                regex: r"([A-Z][a-z][0-9][A-Z][a-z][0-9]{12})".into(),
                group: Some(1),
                ..PatternSpec::default()
            }],
            keywords: Vec::new(),
            ..keyhog_scanner::testing::named_detector_fixture_defaults()
        },
    ];
    let tuning = ScannerTuningConfig {
        no_candidate_gate: Some(false),
        ..ScannerTuningConfig::default()
    };
    let scalar_scanner = CompiledScanner::compile_with_gpu_policy_and_tuning(
        detectors.clone(),
        GpuInitPolicy::SelectedBackend(ScanBackend::CpuFallback),
        &tuning,
    )
    .expect("compile scalar detector plan");
    let simd_scanner = CompiledScanner::compile_with_gpu_policy_and_tuning(
        detectors,
        GpuInitPolicy::SelectedBackend(ScanBackend::SimdCpu),
        &tuning,
    )
    .expect("compile SIMD detector plan");
    let chunk = Chunk::from("value = Qx7Rt9123456789012");
    keyhog_scanner::testing::initialize_phase2_hyperscan_for_test(&simd_scanner);

    let scalar = scalar_scanner
        .scan_coalesced_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .expect("scalar phase-two ownership scan should succeed");
    assert!(
        !keyhog_scanner::testing::phase2_hyperscan_initialized(&scalar_scanner),
        "the scalar route must retain the portable phase-two owner"
    );

    let simd = simd_scanner
        .scan_coalesced_with_backend(&[chunk], ScanBackend::SimdCpu)
        .expect("SIMD phase-two ownership scan should succeed");
    assert_eq!(simd, scalar);
    assert!(
        keyhog_scanner::testing::phase2_hyperscan_initialized(&simd_scanner),
        "the selected SIMD route must own its phase-two Hyperscan engine"
    );
}

#[test]
fn explicit_route_rejects_a_residual_backend_from_another_candidate() {
    let detectors =
        keyhog_core::load_embedded_detectors_or_fail().expect("embedded detector corpus must load");
    let scanner = CompiledScanner::compile(detectors).expect("compile embedded detector plan");
    let chunk = Chunk::from("const api_key = \"sk_live_0123456789abcdefghijklmnopqrstuv\";\n");
    let mismatched = keyhog_scanner::ScanExecutionRoute {
        decode_backend: ScanBackend::SimdCpu,
        ..scanner.execution_route_for_backend(ScanBackend::CpuFallback)
    };

    let error = scanner
        .scan_coalesced_with_backend_admission_and_route(
            &[chunk],
            ScanBackend::CpuFallback,
            None,
            mismatched,
        )
        .expect_err("a scalar route must not borrow SIMD residual execution");
    assert!(
        error.to_string().contains(
            "cpu-fallback route declares simd-regex residual execution, expected cpu-fallback"
        ),
        "route mismatch must identify both backends and the fix: {error}"
    );
}
