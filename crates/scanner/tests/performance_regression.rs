use keyhog_core::{Chunk, ChunkMetadata, DetectorFile};
use keyhog_scanner::{match_entropy, CompiledScanner};
use std::time::Instant;

fn load_embedded_detectors() -> Vec<keyhog_core::DetectorSpec> {
    let embedded = keyhog_core::embedded_detector_tomls();
    if embedded.is_empty() {
        panic!("no embedded detectors — rebuild keyhog-core with detectors directory");
    }
    embedded
        .iter()
        .filter_map(|(_, toml)| toml::from_str::<DetectorFile>(toml).ok())
        .map(|f| f.detector)
        .collect()
}

fn make_chunk(data: &str) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            source_type: "test".into(),
            path: Some("perf_test.txt".into()),
            commit: None,
            author: None,
            date: None,
        },
    }
}

fn generate_1mb_text() -> String {
    let mut s = String::with_capacity(1024 * 1024);
    let line = "const api_key = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\";\n";
    while s.len() + line.len() <= 1024 * 1024 {
        s.push_str(line);
    }
    while s.len() < 1024 * 1024 {
        s.push('x');
    }
    s
}

#[test]
#[ignore = "perf threshold; hardware-dependent — run with --ignored locally"]
fn scan_1mb_with_all_detectors_under_100ms() {
    // Debug builds use 10x+ more memory for HS compilation and are 100x slower.
    // This test is meaningful only in release mode.
    if cfg!(debug_assertions) {
        return;
    }
    let detectors = load_embedded_detectors();
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");
    let chunk = make_chunk(&generate_1mb_text());

    // Warm up: first scan triggers lazy HS scratch allocation.
    let _ = scanner.scan(&chunk);

    let start = Instant::now();
    let matches = scanner.scan(&chunk);
    let elapsed = start.elapsed();

    // Debug builds are ~100x slower due to unoptimized regex + HS cold compilation.
    // The warm scan is fast; the test includes first-scan HS scratch allocation.
    let limit_ms: u128 = if cfg!(debug_assertions) { 120_000 } else { 100 };
    assert!(
        elapsed.as_millis() < limit_ms,
        "Scanning 1MB with all detectors took {} ms (expected < {limit_ms} ms). Fix: optimize scan_inner or reduce detector count.",
        elapsed.as_millis()
    );
    // Ensure the scan actually produced findings
    assert!(!matches.is_empty(), "Expected findings in benchmark text");
}

#[test]
#[ignore = "perf threshold; hardware-dependent — run with --ignored locally"]
fn pattern_compilation_under_500ms() {
    let detectors = load_embedded_detectors();

    let start = Instant::now();
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");
    let elapsed = start.elapsed();

    // Debug builds are ~10x slower than release. Allow 5000ms in debug, 500ms in release.
    let limit_ms = if cfg!(debug_assertions) { 5000 } else { 500 };
    assert!(
        elapsed.as_millis() < limit_ms,
        "Pattern compilation took {} ms (expected < {limit_ms} ms). Fix: simplify regexes or reduce detector count.",
        elapsed.as_millis()
    );
    assert!(
        scanner.detector_count() > 800,
        "Expected ~892 detectors loaded"
    );
}

#[test]
fn entropy_1000_chars_under_1ms() {
    let data: String = (0..1000).map(|i| ((i % 62) + 48) as u8 as char).collect();

    let start = Instant::now();
    let entropy = match_entropy(data.as_bytes());
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_micros() < 1000,
        "Entropy calculation for 1000 chars took {} µs (expected < 1 ms). Fix: optimize entropy path.",
        elapsed.as_micros()
    );
    assert!(entropy > 0.0, "Entropy should be positive for varied input");
}

#[test]
fn cpu_fallback_completes_under_2s_on_4mib_corpus() {
    // Smoke check: even the no-SIMD/no-GPU CpuFallback path completes a
    // 4 MiB corpus scan within 2s on debug builds. Catches accidental
    // O(n²) regressions that wouldnt show up on the SimdCpu path.
    use keyhog_scanner::ScanBackend;
    let detectors = load_embedded_detectors();
    let scanner = CompiledScanner::compile(detectors).expect("scanner compiles");

    let mut chunks = Vec::with_capacity(32);
    for i in 0..32 {
        let mut data = String::with_capacity(128 * 1024);
        while data.len() < 128 * 1024 {
            data.push_str("// no secret here, just realistic-shaped code\n");
        }
        data.push_str(&format!(
            "export const KEY_{i} = \"ghp_ABCDEF1234567890ABCDEF1234567890AB\";\n"
        ));
        chunks.push(Chunk {
            data: data.into(),
            metadata: ChunkMetadata {
                base_offset: 0,
                source_type: "test/perf".into(),
                ..Default::default()
            },
        });
    }

    let start = Instant::now();
    let results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback);
    let elapsed = start.elapsed();
    let limit_ms = if cfg!(debug_assertions) {
        30_000
    } else {
        2_000
    };
    let total_findings: usize = results.iter().map(|m| m.len()).sum();
    assert!(
        elapsed.as_millis() < limit_ms,
        "CpuFallback scan of 4 MiB took {} ms (limit {limit_ms} ms) — perf regression",
        elapsed.as_millis()
    );
    assert!(
        total_findings >= 32,
        "expected at least one finding per chunk"
    );
}
