#![cfg(not(feature = "gpu"))]

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScanError};

const CHILD_ENV: &str = "KEYHOG_COMPILED_SCANNER_BACKEND_ERROR_CHILD";
const TEST_NAME: &str = "regression_compiled_scanner_backend_errors::selected_backend_failure_returns_error_without_terminating_host";
const CHILD_ALIVE_MARKER: &str = "compiled-scanner-host-remained-alive";

fn scanner_and_matching_chunk(backend: ScanBackend) -> (CompiledScanner, Chunk) {
    let detector = DetectorSpec {
        tests: Vec::new(),
        id: "compiled-scanner-backend-error".into(),
        name: "Compiled scanner backend error".into(),
        service: "regression".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "tok".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["tok".into()],
        min_confidence: Some(0.1),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let scanner = CompiledScanner::compile_for_backend(vec![detector], backend)
        .expect("regression detector compiles for the selected backend");
    let chunk = Chunk {
        data: "tok=abc".into(),
        metadata: ChunkMetadata::default(),
    };
    (scanner, chunk)
}

/// Regression: selecting an unavailable GPU backend used to exit the entire
/// embedding process; the child must observe `ScanError` and continue running.
#[test]
fn selected_backend_failure_returns_error_without_terminating_host() {
    if std::env::var_os(CHILD_ENV).is_some() {
        let (gpu_scanner, chunk) = scanner_and_matching_chunk(ScanBackend::GpuCuda);
        let error = gpu_scanner
            .scan_with_backend(&chunk, ScanBackend::GpuCuda)
            .expect_err("a build without gpu must reject the selected GPU backend");
        assert!(
            matches!(error, ScanError::Gpu(_)),
            "backend failure must retain its structured GPU classification: {error}"
        );

        let batch_error = gpu_scanner
            .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::GpuCuda)
            .expect_err("batch dispatch must use the same fallible backend boundary");
        assert!(
            matches!(batch_error, ScanError::Gpu(_)),
            "batch failure must retain its structured GPU classification: {batch_error}"
        );

        #[cfg(not(feature = "simd"))]
        {
            let (simd_scanner, _) = scanner_and_matching_chunk(ScanBackend::SimdCpu);
            let simd_error = simd_scanner
                .scan_with_backend(&chunk, ScanBackend::SimdCpu)
                .expect_err("a build without SIMD must reject the selected SIMD backend");
            assert!(
                matches!(simd_error, ScanError::Simd(_)),
                "SIMD failure must retain its structured classification: {simd_error}"
            );
        }

        let (cpu_scanner, _) = scanner_and_matching_chunk(ScanBackend::CpuFallback);
        let matches = cpu_scanner
            .scan_with_backend(&chunk, ScanBackend::CpuFallback)
            .expect("the host can keep using the scanner after the backend error");
        assert_eq!(
            matches.len(),
            1,
            "continued host execution must remain useful"
        );
        println!("{CHILD_ALIVE_MARKER}");
        return;
    }

    let output = std::process::Command::new(
        std::env::current_exe().expect("current scanner test executable is available"),
    )
    .env(CHILD_ENV, "1")
    .arg(TEST_NAME)
    .arg("--exact")
    .arg("--test-threads=1")
    .arg("--nocapture")
    .output()
    .expect("isolated compiled-scanner regression process starts");

    assert!(
        output.status.success(),
        "scanner backend failure terminated or failed the embedding process\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(CHILD_ALIVE_MARKER),
        "child never reached code after the returned scanner error\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Regression: making the established selected-backend API fallible must not
/// change successful CPU findings relative to the portable reference API.
#[test]
fn fallible_backend_scan_preserves_success_results() {
    let (scanner, chunk) = scanner_and_matching_chunk(ScanBackend::CpuFallback);
    let reference = scanner
        .scan(&chunk)
        .expect("portable reference scan remains available");
    let selected = scanner
        .scan_with_backend(&chunk, ScanBackend::CpuFallback)
        .expect("CPU fallback remains available");

    assert_eq!(selected, reference);
    assert_eq!(
        selected.len(),
        1,
        "the comparison must exercise a real finding"
    );
}
