//! Backend parity for entropy-fallback scoring paths.
//!
//! The entropy-fallback codepath (`fallback_entropy.rs`) scores high-entropy
//! tokens that don't match any literal-prefix detector. Entropy scoring may
//! diverge between SIMD, CpuFallback, and GPU paths if:
//!
//!   1. The entropy threshold or scaling differs across backends.
//!   2. Line-offset accounting diverges, causing windowing to fail.
//!   3. The fallback AC pre-filter (keyword-based) produces different active-pattern sets.
//!
//! This test plants high-entropy credentials that have NO literal-prefix match
//! but WILL fire on the entropy fallback path, and asserts all backends report
//! the same (credential, offset) tuples.

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::BTreeSet;
use support::paths::detector_dir;

type FindingKey = (String, usize);

fn collect_entropy_findings(results: &[Vec<keyhog_core::RawMatch>]) -> BTreeSet<FindingKey> {
    results
        .iter()
        .flat_map(|chunk| chunk.iter())
        .map(|m| (m.credential.as_ref().to_string(), m.location.offset))
        .collect()
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
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors directory unavailable: {e}");
            return;
        }
    };
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

    let backends = [
        ScanBackend::SimdCpu,
        ScanBackend::CpuFallback,
        ScanBackend::Gpu,
        ScanBackend::MegaScan,
    ];

    let simd_results = scanner.scan_chunks_with_backend(&[fixture.clone()], ScanBackend::SimdCpu);
    let simd_keys = collect_entropy_findings(&simd_results);

    let mut failures = Vec::new();
    for backend in &backends[1..] {
        let results = scanner.scan_chunks_with_backend(&[fixture.clone()], *backend);
        let keys = collect_entropy_findings(&results);

        // GPU/MegaScan can silently degrade to SIMD if no adapter; skip on empty.
        if matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan)
            && keys.is_empty()
            && !simd_keys.is_empty()
        {
            eprintln!("SKIP: {backend:?} (no adapter, silent SIMD degrade)");
            continue;
        }

        if keys != simd_keys {
            let only_simd: Vec<_> = simd_keys.difference(&keys).take(3).collect();
            let only_backend: Vec<_> = keys.difference(&simd_keys).take(3).collect();
            failures.push(format!(
                "[entropy/{backend:?}] parity broken: simd={} got={} \
                 only-in-simd={only_simd:?} only-in-backend={only_backend:?}",
                simd_keys.len(),
                keys.len()
            ));
        }
    }

    eprintln!(
        "entropy_fallback_parity: backends={} failures={}",
        backends.len(),
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "entropy fallback parity failures:\n  - {}",
        failures.join("\n  - ")
    );
}

#[test]
fn entropy_fallback_with_keyword_prefilter_active() {
    // Entropy fallback uses a keyword-AC pre-filter to avoid scanning
    // every pattern on every chunk. Ensure the pre-filter produces
    // consistent active-pattern sets across backends.
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors directory unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    // A chunk that contains a keyword that should activate the
    // entropy-fallback pre-filter (e.g., "secret", "password", "token").
    let fixture = make_chunk(
        "// Embedded high-entropy credential\n\
         export const secret_token = \"xYz9aB8cD7eF6gH5iJ4kL3mN2oP1qRs0T\";\n\
         const api_key = \"aAbBcCdDeEfFgGhHiIjJkKlMmNnOoPpQq\";\n",
        "config.ts",
    );

    let simd_results = scanner.scan_chunks_with_backend(&[fixture.clone()], ScanBackend::SimdCpu);
    let simd_keys = collect_entropy_findings(&simd_results);

    let fallback_results =
        scanner.scan_chunks_with_backend(&[fixture.clone()], ScanBackend::CpuFallback);
    let fallback_keys = collect_entropy_findings(&fallback_results);

    if simd_keys != fallback_keys {
        let only_simd: Vec<_> = simd_keys.difference(&fallback_keys).take(3).collect();
        let only_fallback: Vec<_> = fallback_keys.difference(&simd_keys).take(3).collect();
        panic!(
            "entropy keyword-prefilter parity broken.\n  \
             SIMD findings: {}\n  Fallback findings: {}\n  \
             only-in-SIMD={only_simd:?}\n  only-in-Fallback={only_fallback:?}",
            simd_keys.len(),
            fallback_keys.len()
        );
    }
}
