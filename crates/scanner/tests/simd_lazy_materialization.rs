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
