//! Diagnostic for the SIMD/GPU parity divergence reported by
//! `gpu_and_simd_produce_identical_findings_on_same_corpus` (gpu_parity.rs:108):
//! SIMD finds `sb_4bZ39EnIvgTAxogqQ1wam7az` in the `payload: …` chunk,
//! GPU does not. The literal `sb_` doesn't appear in any test chunk
//! we feed in, so the finding is being synthesised by some
//! detector/decode/fallback path.
//!
//! This test prints every finding from both backends with detector
//! ID and credential so we can see which detector is producing it and
//! why the GPU path misses it.

mod support;
use support::contracts::test_chunk as make_chunk;
use support::paths::detector_dir;

use keyhog_scanner::{CompiledScanner, ScanBackend};

#[test]
fn diagnose_sb_divergence_chunk2_only() {
    let Ok(detectors) = keyhog_core::load_detectors(&detector_dir()) else {
        eprintln!("SKIP: detectors directory unavailable");
        return;
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    // The chunk that the parity test attributes the missing finding to.
    let chunk = make_chunk(
        "auth: \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\npayload: \"AKIAQYLPMN5HFIQR7BBB\"",
        "fixtures/stripe_aws.yml",
    );

    let simd = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let gpu = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu);

    eprintln!("=== SIMD ===");
    for chunk_matches in &simd {
        for m in chunk_matches {
            eprintln!(
                "  detector={} service={} cred={:?} offset={} line={:?}",
                m.detector_id.as_ref(),
                m.service.as_ref(),
                m.credential.as_ref(),
                m.location.offset,
                m.location.line,
            );
        }
    }
    eprintln!("=== GPU ===");
    for chunk_matches in &gpu {
        for m in chunk_matches {
            eprintln!(
                "  detector={} service={} cred={:?} offset={} line={:?}",
                m.detector_id.as_ref(),
                m.service.as_ref(),
                m.credential.as_ref(),
                m.location.offset,
                m.location.line,
            );
        }
    }

    let simd_n: usize = simd.iter().map(|c| c.len()).sum();
    let gpu_n: usize = gpu.iter().map(|c| c.len()).sum();
    eprintln!("=== TOTALS: SIMD={simd_n}, GPU={gpu_n} ===");

    // Don't assert - this is a diagnostic, not a gate. The actual
    // gate is in gpu_parity.rs.
}

#[test]
fn simd_sb_hallucinates_with_no_sb_in_input() {
    // Stripped-down corpus: ONLY content with no `sb_` and no
    // stackblitz/STACKBLITZ keyword. If SIMD still surfaces a
    // stackblitz-credentials finding, that's a Hyperscan FP and the
    // bug is on the SIMD side (not a GPU gap).
    let Ok(detectors) = keyhog_core::load_detectors(&detector_dir()) else {
        eprintln!("SKIP: detectors directory unavailable");
        return;
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    let chunk = make_chunk(
        "auth: \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"",
        "fixtures/stripe.yml",
    );

    let simd = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let mut stackblitz_findings = 0;
    for chunk_matches in &simd {
        for m in chunk_matches {
            if m.detector_id.as_ref().contains("stackblitz") {
                stackblitz_findings += 1;
                eprintln!(
                    "  STACKBLITZ FP: cred={:?} offset={} line={:?} detector={}",
                    m.credential.as_ref(),
                    m.location.offset,
                    m.location.line,
                    m.detector_id.as_ref(),
                );
            }
        }
    }
    assert_eq!(
        stackblitz_findings, 0,
        "SIMD surfaced a stackblitz-credentials finding on a chunk with no `sb_` prefix and no stackblitz keyword. That's a Hyperscan/SIMD false positive; the credential text is synthesised from somewhere other than the input.",
    );
}
