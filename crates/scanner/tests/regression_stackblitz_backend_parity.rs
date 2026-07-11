//! Regression for a former synthesized StackBlitz finding and SIMD/GPU
//! divergence. The reproducer now gates exact complete-finding parity and the
//! negative twin proves a StackBlitz finding cannot appear without its prefix.

mod support;
use support::contracts::test_chunk as make_chunk;
use support::paths::detector_dir;

use keyhog_scanner::{CompiledScanner, ScanBackend};

#[test]
#[cfg(feature = "gpu")]
fn stripe_aws_reproducer_has_exact_gpu_simd_parity_without_degrade() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    // The chunk that the parity test attributes the missing finding to.
    let chunk = make_chunk(
        "auth: \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\npayload: \"AKIAQYLPMN5HFIQR7BBB\"",
        "fixtures/stripe_aws.yml",
    );

    let canonical = |chunks: &[Vec<keyhog_core::RawMatch>]| {
        let mut findings = chunks.iter().flatten().cloned().collect::<Vec<_>>();
        findings.sort();
        findings
    };
    scanner.clear_fragment_cache();
    let simd = canonical(&scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu));
    scanner.clear_fragment_cache();
    let degrade_before = scanner.runtime_status().gpu_degrade_count;
    let gpu = canonical(&scanner.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu));
    let degrade_after = scanner.runtime_status().gpu_degrade_count;

    assert_eq!(
        degrade_after, degrade_before,
        "GPU reproducer must not silently substitute CPU"
    );
    assert_eq!(
        gpu, simd,
        "GPU and SimdCpu must agree on every RawMatch field and multiplicity"
    );
}

#[test]
fn simd_sb_hallucinates_with_no_sb_in_input() {
    // Stripped-down corpus: ONLY content with no `sb_` and no
    // stackblitz/STACKBLITZ keyword. If SIMD still surfaces a
    // stackblitz-credentials finding, that's a Hyperscan FP and the
    // bug is on the SIMD side (not a GPU gap).
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
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
