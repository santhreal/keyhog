//! Backend parity for entropy-fallback scoring paths.
//!
//! The entropy-fallback codepath (`phase2_entropy.rs`) scores high-entropy
//! tokens that don't match any literal-prefix detector. Entropy scoring may
//! diverge between SIMD, CpuFallback, and GPU paths if:
//!
//!   1. The entropy threshold or scaling differs across backends.
//!   2. Line-offset accounting diverges, causing windowing to fail.
//!   3. The fallback AC pre-filter (keyword-based) produces different active-pattern sets.
//!
//! This test plants high-entropy credentials that have no vendor literal-prefix
//! match but do fire on the generic/entropy path, and asserts complete RawMatch
//! equality, multiplicity, and no GPU degradation.

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use support::paths::detector_dir;

fn collect_entropy_findings(results: &[Vec<keyhog_core::RawMatch>]) -> Vec<keyhog_core::RawMatch> {
    let mut findings = results.iter().flatten().cloned().collect::<Vec<_>>();
    findings.sort();
    findings
}

fn make_chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "entropy-test".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

#[test]
fn entropy_fallback_parity_high_entropy_no_literal_prefix() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    // High-entropy string that does NOT match any literal-prefix detector.
    // This forces reliance on the entropy-fallback path. Using a 32-char
    // random-looking token (high entropy, no AKIA/sk_/ghp_ prefix).
    let high_entropy_token = "KmXpQrWsTuVwXyZaBcDeFgHiJkLmNoP";
    let fixture = make_chunk(
        &format!(
            "// Random token embedded in code\n\
             const secret = \"{}\";\n\
             function setup() {{\n\
               const token = \"{}\";\n\
               return token;\n\
             }}\n",
            high_entropy_token, high_entropy_token
        ),
        "entropy_case.js",
    );

    let mut backends = vec![ScanBackend::CpuFallback];
    #[cfg(feature = "gpu")]
    backends.extend([ScanBackend::Gpu, ScanBackend::MegaScan]);

    scanner.clear_fragment_cache();
    let simd_results = scanner.scan_chunks_with_backend(&[fixture.clone()], ScanBackend::SimdCpu);
    let simd_findings = collect_entropy_findings(&simd_results);
    assert!(
        simd_findings
            .iter()
            .any(|finding| finding.credential.as_ref() == high_entropy_token),
        "entropy fixture must surface the planted token before parity is meaningful"
    );

    for backend in backends {
        scanner.clear_fragment_cache();
        let degrade_before = scanner.runtime_status().gpu_degrade_count;
        let results = scanner.scan_chunks_with_backend(&[fixture.clone()], backend);
        let degrade_after = scanner.runtime_status().gpu_degrade_count;
        let findings = collect_entropy_findings(&results);

        if matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan) {
            assert_eq!(
                degrade_after, degrade_before,
                "{backend:?} entropy proof must not silently substitute CPU"
            );
        }
        assert_eq!(
            findings, simd_findings,
            "{backend:?} must preserve every entropy-path RawMatch field and multiplicity"
        );
    }
}

#[test]
fn entropy_fallback_with_keyword_prefilter_active() {
    // Entropy fallback uses a keyword-AC pre-filter to avoid scanning
    // every pattern on every chunk. Ensure the pre-filter produces
    // consistent active-pattern sets across backends.
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    // A chunk that contains a keyword that should activate the
    // entropy-fallback pre-filter (e.g., "secret", "password", "token").
    let fixture = make_chunk(
        "// Embedded high-entropy credential\n\
         export const secret_token = \"xYz9aB8cD7eF6gH5iJ4kL3mN2oP1qRs0T\";\n\
         const api_key = \"aAbBcCdDeEfFgGhHiIjJkKlMmNnOoPpQq\";\n",
        "config.ts",
    );

    scanner.clear_fragment_cache();
    let simd_results = scanner.scan_chunks_with_backend(&[fixture.clone()], ScanBackend::SimdCpu);
    let simd_findings = collect_entropy_findings(&simd_results);
    assert!(
        !simd_findings.is_empty(),
        "keyword-prefilter fixture must produce at least one reference finding"
    );

    scanner.clear_fragment_cache();
    let fallback_results =
        scanner.scan_chunks_with_backend(&[fixture.clone()], ScanBackend::CpuFallback);
    let fallback_findings = collect_entropy_findings(&fallback_results);

    assert_eq!(
        fallback_findings, simd_findings,
        "keyword-prefilter path must preserve every RawMatch field and multiplicity"
    );
}
