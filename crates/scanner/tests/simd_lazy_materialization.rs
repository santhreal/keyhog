#![cfg(feature = "simd")]

use keyhog_core::{Chunk, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn scanner() -> CompiledScanner {
    CompiledScanner::compile(vec![DetectorSpec {
        id: "simd-lazy-peer".into(),
        name: "SIMD lazy peer".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "KHSIMDLAZY_[A-Za-z0-9]{20}".into(),
            ..PatternSpec::default()
        }],
        keywords: vec!["KHSIMDLAZY".into()],
        ..DetectorSpec::default()
    }])
    .expect("compile scanner plan")
}

#[test]
fn scalar_execution_does_not_materialize_hyperscan_but_selected_simd_does() {
    let scanner = scanner();
    assert!(scanner.simd_backend_available());
    assert!(!scanner.simd_backend_initialized());

    let chunk = Chunk::from("token=KHSIMDLAZY_A1b2C3d4E5f6G7h8I9j0");
    let scalar =
        scanner.scan_coalesced_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback);
    assert_eq!(scalar[0].len(), 1);
    assert!(
        !scanner.simd_backend_initialized(),
        "a scalar route must not pay Hyperscan initialization"
    );

    assert!(scanner.warm_backend(ScanBackend::SimdCpu));
    assert!(scanner.simd_backend_initialized());
    assert!(scanner.simd_initialization_ns().is_some_and(|ns| ns > 0));
    let simd = scanner.scan_coalesced_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_eq!(simd, scalar);
}

#[test]
fn selected_simd_without_a_plan_returns_the_exact_typed_error() {
    let scanner = CompiledScanner::compile(Vec::new()).expect("compile empty detector corpus");
    let error = scanner
        .try_scan_coalesced_with_backend_and_admission(
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
    let detectors =
        keyhog_core::load_embedded_detectors_or_fail().expect("embedded detector corpus must load");
    let scanner = CompiledScanner::compile(detectors).expect("compile embedded detector plan");
    let chunk = Chunk::from("const api_key = \"sk_live_0123456789abcdefghijklmnopqrstuv\";\n");

    let scalar =
        scanner.scan_coalesced_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback);
    assert!(
        !scalar[0].is_empty(),
        "fixture must exercise real phase two"
    );
    assert!(
        !keyhog_scanner::testing::phase2_hyperscan_initialized(&scanner),
        "the scalar route must retain the portable phase-two owner"
    );

    let simd = scanner.scan_coalesced_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_eq!(simd, scalar);
    assert!(
        keyhog_scanner::testing::phase2_hyperscan_initialized(&scanner),
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
        .try_scan_coalesced_with_backend_admission_and_route(
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
