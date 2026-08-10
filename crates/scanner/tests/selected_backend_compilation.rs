use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn detector() -> DetectorSpec {
    DetectorSpec {
        id: "selected-route-test".into(),
        name: "Selected Route Test".into(),
        service: "test".into(),
        severity: Severity::Medium,
        patterns: vec![PatternSpec {
            regex: r"STATIC_SECRET_[0-9]+".into(),
            ..Default::default()
        }],
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }
}

fn chunk() -> Chunk {
    Chunk {
        data: "token = STATIC_SECRET_12345".to_owned().into(),
        metadata: ChunkMetadata {
            path: Some("fixture.txt".into()),
            ..Default::default()
        },
    }
}

/// WHY: exact scanners must discard every unselected GPU slot, while a selected GPU retains one diagnostic peer even when that platform cannot acquire it.
#[test]
fn selected_scanners_expose_only_their_exact_gpu_backend_state() {
    let mut backends = vec![ScanBackend::CpuFallback];
    #[cfg(feature = "simd")]
    backends.push(ScanBackend::SimdCpu);

    for backend in backends {
        let scanner = CompiledScanner::compile_for_backend(vec![detector()], backend)
            .expect("compile exact host-route scanner");
        assert_eq!(scanner.gpu_backend_candidates(), Vec::new());
        assert_eq!(
            scanner.runtime_status().gpu_backends,
            keyhog_scanner::GpuBackendAvailability::default()
        );
    }

    #[cfg(target_os = "macos")]
    let unavailable_gpu = ScanBackend::GpuCuda;
    #[cfg(not(target_os = "macos"))]
    let unavailable_gpu = ScanBackend::GpuMetal;
    let scanner = CompiledScanner::compile_for_backend(vec![detector()], unavailable_gpu)
        .expect("compile exact unavailable GPU-route scanner");
    let candidates = scanner.gpu_backend_candidates();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].backend, unavailable_gpu);
    assert!(!candidates[0].available);
    assert!(!candidates[0].acquired);
    assert!(candidates[0].acquisition_error.is_some());
}

/// WHY: a route-specific scanner must preserve the selected backend's real findings while refusing to materialize or dispatch another route.
#[test]
fn cpu_scanner_executes_cpu_and_rejects_simd_substitution() {
    let scanner = CompiledScanner::compile_for_backend(vec![detector()], ScanBackend::CpuFallback)
        .expect("compile CPU-only scanner");
    let findings = scanner
        .scan_with_backend(&chunk(), ScanBackend::CpuFallback)
        .expect("scan selected CPU route");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].detector_id.as_ref(), "selected-route-test");
    assert_eq!(findings[0].location.offset, 8);
    assert_eq!(
        findings[0].location.file_path.as_deref(),
        Some("fixture.txt")
    );

    let error = scanner
        .scan_with_backend(&chunk(), ScanBackend::SimdCpu)
        .expect_err("unselected SIMD route must fail");
    assert!(error
        .to_string()
        .contains("materialized backend cpu-fallback"));
    assert!(error.to_string().contains("dispatch requested simd-regex"));
    assert!(error
        .to_string()
        .contains("runtime backend substitution is forbidden"));
}

/// WHY: SIMD selection must not be represented as a universal scanner that later accepts scalar top-level routing by accident.
#[cfg(feature = "simd")]
#[test]
fn simd_scanner_rejects_cpu_top_level_substitution() {
    let scanner = CompiledScanner::compile_for_backend(vec![detector()], ScanBackend::SimdCpu)
        .expect("compile SIMD-only scanner");
    let error = scanner
        .scan_with_backend(&chunk(), ScanBackend::CpuFallback)
        .expect_err("unselected CPU route must fail");
    assert!(error
        .to_string()
        .contains("materialized backend simd-regex"));
    assert!(error
        .to_string()
        .contains("dispatch requested cpu-fallback"));
}
