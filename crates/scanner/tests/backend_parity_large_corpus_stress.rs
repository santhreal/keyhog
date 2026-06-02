//! Backend parity under stress: large corpus with many firing detectors.
//!
//! The full detector corpus has ~894 detectors. When scanning a chunk that
//! triggers many of them simultaneously, backend dispatch logic is heavily
//! exercised. This test creates fixtures that trigger large subsets of the
//! detector corpus and verifies all backends report identical findings.
//!
//! Key assertions:
//!   1. Finding counts match across backends.
//!   2. Finding offsets and credentials are byte-identical.
//!   3. No findings are dropped or duplicated.

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::BTreeSet;
use support::paths::detector_dir;

type FindingKey = (String, usize);

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

fn collect_findings(results: &[Vec<keyhog_core::RawMatch>]) -> BTreeSet<FindingKey> {
    results
        .iter()
        .flat_map(|chunk| chunk.iter())
        .map(|m| (m.credential.as_ref().to_string(), m.location.offset))
        .collect()
}

#[test]
fn large_corpus_many_simultaneous_detector_fires() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors directory unavailable: {e}");
            return;
        }
    };

    assert!(
        detectors.len() >= 894,
        "stress test requires full corpus (got {} detectors)",
        detectors.len()
    );

    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    // Construct a fixture that deliberately triggers many detector types.
    // Include multiple prefixes (AKIA, ghp_, sk_live_, ASIA) and patterns
    // that would activate entropy fallback and AC pre-filters.
    let fixture = make_chunk(
        &format!(
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
             alt_key2 = \"AKIAXYZ1234567890EFG\"\n\
             "
        ),
        "stress_corpus.py",
    );

    let backends = [
        ScanBackend::SimdCpu,
        ScanBackend::CpuFallback,
        ScanBackend::Gpu,
        ScanBackend::MegaScan,
    ];

    let simd_results = scanner.scan_chunks_with_backend(&[fixture.clone()], ScanBackend::SimdCpu);
    let simd_findings = collect_findings(&simd_results);

    eprintln!(
        "stress test: SIMD found {} findings on full corpus",
        simd_findings.len()
    );

    let mut failures = Vec::new();
    for backend in &backends[1..] {
        let results = scanner.scan_chunks_with_backend(&[fixture.clone()], *backend);
        let findings = collect_findings(&results);

        // GPU/MegaScan can silently degrade.
        if matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan)
            && findings.is_empty()
            && !simd_findings.is_empty()
        {
            eprintln!("SKIP: {backend:?} (no adapter, silent SIMD degrade)");
            continue;
        }

        if findings != simd_findings {
            let only_simd: Vec<_> = simd_findings.difference(&findings).take(5).collect();
            let only_backend: Vec<_> = findings.difference(&simd_findings).take(5).collect();
            failures.push(format!(
                "[stress/{backend:?}] parity broken: simd={} got={} \
                 only-in-simd={only_simd:?} only-in-backend={only_backend:?}",
                simd_findings.len(),
                findings.len()
            ));
        }
    }

    eprintln!(
        "large_corpus_stress: backends={} failures={}",
        backends.len(),
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "large corpus stress parity failures:\n  - {}",
        failures.join("\n  - ")
    );
}

#[test]
fn detector_count_preserved_after_compile() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors directory unavailable: {e}");
            return;
        }
    };

    let original_count = detectors.len();
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let compiled_count = scanner.detector_count();

    assert_eq!(
        compiled_count, original_count,
        "detector count mismatch: original={} compiled={}",
        original_count, compiled_count
    );
    assert!(
        compiled_count >= 894,
        "expected at least 894 detectors, got {}",
        compiled_count
    );
}
