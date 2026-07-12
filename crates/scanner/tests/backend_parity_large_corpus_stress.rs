//! Backend parity under stress: large corpus with many firing detectors.
//!
//! When scanning a chunk that triggers many detector families simultaneously,
//! backend dispatch logic is heavily
//! exercised. This test creates fixtures that trigger large subsets of the
//! detector corpus and verifies all backends report identical findings.
//!
//! Key assertions:
//!   1. Complete RawMatch values match across backends.
//!   2. Finding multiplicity is preserved.
//!   3. Forced GPU routes do not degrade to CPU.

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use support::paths::detector_dir;

fn make_chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "stress-test".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

fn collect_findings(results: &[Vec<keyhog_core::RawMatch>]) -> Vec<keyhog_core::RawMatch> {
    let mut findings = results.iter().flatten().cloned().collect::<Vec<_>>();
    findings.sort();
    findings
}

#[test]
fn large_corpus_many_simultaneous_detector_fires() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");

    assert_eq!(
        detectors.len(),
        keyhog_core::embedded_detector_count(),
        "stress test must use the same complete corpus embedded by this build"
    );

    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    // Construct a fixture that deliberately triggers many detector types.
    // Include multiple prefixes (AKIA, ghp_, sk_live_, ASIA) and patterns
    // that would activate entropy fallback and AC pre-filters.
    let fixture = make_chunk(
        "# AWS key\n\
             AWS_KEY = \"AKIAQYLPMN5HFIQR7AAA\"\n\
             \n\
             # GitHub PAT\n\
             TOKEN = \"ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX\"\n\
             \n\
             # Stripe API key\n\
             stripe = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\n\
             \n\
             # AWS STS session token\n\
             session = \"ASIA1234567890ABCDEF\"\n\
             \n\
             # High-entropy fallback token\n\
             secret = \"xYz9aB8cD7eF6gH5iJ4kL3mN2oP1qRs0TuVwXyZ\"\n\
             \n\
             # PEM private key (if detector is available)\n\
             -----BEGIN RSA PRIVATE KEY-----\n\
             MIIEpAIBAAKCAQEA2a2rwplBdL1mK5m2xDplKf7HYFwPeO9XL2K8Zw1pxvkN\n\
             -----END RSA PRIVATE KEY-----\n\
             \n\
             # Additional AWS key variations\n\
             alt_key1 = \"AKIAXYZ1234567890BCD\"\n\
             alt_key2 = \"AKIAXYZ1234567890EFG\"\n",
        "stress_corpus.py",
    );

    let mut backends = vec![ScanBackend::CpuFallback];
    #[cfg(feature = "gpu")]
    backends.extend([ScanBackend::Gpu]);

    scanner.clear_fragment_cache();
    let simd_results = scanner.scan_chunks_with_backend(&[fixture.clone()], ScanBackend::SimdCpu);
    let simd_findings = collect_findings(&simd_results);
    assert!(
        simd_findings
            .iter()
            .any(|finding| finding.detector_id.as_ref() == "stripe-secret-key"),
        "stress reference must prove positive detector truth, not vacuous parity"
    );

    for backend in backends {
        scanner.clear_fragment_cache();
        let degrade_before = scanner.runtime_status().gpu_degrade_count;
        let results = scanner.scan_chunks_with_backend(&[fixture.clone()], backend);
        let degrade_after = scanner.runtime_status().gpu_degrade_count;
        let findings = collect_findings(&results);

        if matches!(backend, ScanBackend::Gpu) {
            assert_eq!(
                degrade_after, degrade_before,
                "{backend:?} stress proof must not silently substitute CPU"
            );
        }
        assert_eq!(
            findings, simd_findings,
            "{backend:?} must preserve every RawMatch field and multiplicity"
        );
    }
}

#[test]
fn detector_count_preserved_after_compile() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");

    let original_count = detectors.len();
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let compiled_count = scanner.runtime_status().detector_count;

    assert_eq!(
        compiled_count, original_count,
        "detector count mismatch: original={} compiled={}",
        original_count, compiled_count
    );
    assert_eq!(compiled_count, keyhog_core::embedded_detector_count());
}
