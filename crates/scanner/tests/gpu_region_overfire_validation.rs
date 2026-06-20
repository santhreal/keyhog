#![cfg(feature = "gpu")]
//! LANE 1 (GPU CORRECTNESS) — live GPU≡SIMD on a real multi-detector corpus,
//! pinning the region-presence GPU path in `engine/gpu_region_dispatch.rs`.
//!
//! Two contracts the validated trigger production must hold (both Law 10):
//!
//! 1. **Finding-set equality** — the GPU path's finding set is IDENTICAL to the
//!    SIMD path's on a corpus that mixes real secrets, GPU over-fire bait (a
//!    detector literal with NO valid body), and clean files. The wave-1 masking
//!    dropped one finding (523 vs 524) by trusting the GPU exclusively; the
//!    recall floor closes that, so neither backend may have a finding the other
//!    lacks.
//!
//! 2. **No over-firing inflation** — the GPU path's user-visible findings come
//!    ONLY from chunks where the detector truly matches. The over-fire-bait chunk
//!    (`ghp_` literal, no 36-char body) must produce ZERO findings on BOTH
//!    backends. Region presence is allowed to produce a candidate bit; the shared
//!    phase-2 extractor must reject it.
//!
//! These run on a live adapter; gated by the explicit require-GPU runtime policy
//! to hard-fail in CI that mandates a GPU, else skipped (no silent CPU
//! masquerade — the GPU path is exercised explicitly via `ScanBackend::Gpu`).
//!
//! Run: cargo test -p keyhog-scanner --features gpu --test gpu_region_overfire_validation -- --nocapture

#[path = "support/mod.rs"]
mod support;

use keyhog_scanner::{CompiledScanner, ScanBackend};
use support::contracts::test_chunk;
use support::gpu_gate::require_gpu_or_panic;
use support::paths::detector_dir;

/// (credential, file_path, offset) — the user-visible finding identity, matching
/// `gpu_parity.rs`. Detector id is intentionally excluded (a literal can attribute
/// to a different detector when prefixes overlap; the credential + location is the
/// product surface).
type FindingKey = (String, String, usize);

fn keys(results: &[Vec<keyhog_core::RawMatch>]) -> std::collections::BTreeSet<FindingKey> {
    let mut set = std::collections::BTreeSet::new();
    for chunk in results {
        for m in chunk {
            set.insert((
                m.credential.as_ref().to_string(),
                m.location
                    .file_path
                    .as_deref()
                    .map(str::to_string)
                    .unwrap_or_default(),
                m.location.offset,
            ));
        }
    }
    set
}

fn scanner() -> CompiledScanner {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("detectors directory must load");
    CompiledScanner::compile(detectors).expect("scanner compile")
}

/// The core lane gate: GPU finding set ≡ SIMD finding set on a corpus that
/// deliberately includes GPU over-fire bait. Any divergence — a GPU under-fire
/// (the 523-vs-524 recall drop) OR a GPU-only finding (over-fire reaching
/// phase-2) — fails with the exact diff.
#[test]
fn gpu_equals_simd_on_overfire_bait_corpus() {
    require_gpu_or_panic("gpu_equals_simd_on_overfire_bait_corpus");
    let scanner = scanner();

    let valid_ghp = "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"; // ghp_ + 36 checksum-valid body
    assert_eq!(valid_ghp.len(), 40, "ghp_ token must be 40 chars");

    let chunks = vec![
        // Real GitHub PAT — a finding on BOTH backends.
        test_chunk(
            &format!("const TOKEN = \"{valid_ghp}\";"),
            "fixtures/real_pat.rs",
        ),
        // OVER-FIRE BAIT: the `ghp_` literal Hyperscan keys on, but the body is
        // far too short for `ghp_[A-Za-z0-9]{36}`. The unanchored GPU DFA fires
        // along the prefix; validation must drop it so it never reaches phase-2.
        // ZERO findings expected on both backends.
        test_chunk(
            "note: the prefix ghp_ is mentioned but ghp_short is not a token",
            "fixtures/overfire_bait.md",
        ),
        // Real AWS key — exercises a second detector class (AKIA).
        test_chunk(
            "aws_access_key_id = AKIAQYLPMN5HFIQR7XYA",
            "fixtures/aws.ini",
        ),
        // Clean file — no detector literal at all.
        test_chunk("fn main() { println!(\"hello, world\"); }", "src/clean.rs"),
    ];

    let simd = keys(&scanner.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu));
    let gpu = keys(&scanner.scan_chunks_with_backend(&chunks, ScanBackend::Gpu));

    // The real PAT must be found by SIMD (sanity: the corpus has a finding).
    assert!(
        simd.iter().any(|(cred, _, _)| cred == valid_ghp),
        "SIMD must find the valid ghp_ PAT; got {simd:?}"
    );
    // The over-fire bait must NOT appear as a finding on either backend.
    assert!(
        !simd
            .iter()
            .any(|(_, path, _)| path == "fixtures/overfire_bait.md"),
        "SIMD must not surface a finding in the over-fire bait file: {simd:?}"
    );
    assert!(
        !gpu.iter()
            .any(|(_, path, _)| path == "fixtures/overfire_bait.md"),
        "GPU must not surface a finding in the over-fire bait file (validation \
         dropped the over-fire): {gpu:?}"
    );

    if simd != gpu {
        let only_simd: Vec<_> = simd.difference(&gpu).collect();
        let only_gpu: Vec<_> = gpu.difference(&simd).collect();
        panic!(
            "GPU≢SIMD on the over-fire-bait corpus.\n  SIMD findings: {}\n  GPU findings:  {}\n  \
             only in SIMD (GPU under-fire / recall drop) ({}): {:?}\n  \
             only in GPU (over-fire reached phase-2) ({}): {:?}",
            simd.len(),
            gpu.len(),
            only_simd.len(),
            only_simd,
            only_gpu.len(),
            only_gpu,
        );
    }
}

/// Boundary-straddled secret parity through the GPU path with the over-fire bait
/// present, proving the validated trigger production does not break cross-chunk
/// reassembly (the boundary scan runs AFTER phase-2 on the GPU path too).
#[test]
fn gpu_equals_simd_with_repeated_real_secrets() {
    require_gpu_or_panic("gpu_equals_simd_with_repeated_real_secrets");
    let scanner = scanner();

    // Several real PATs across many chunks so the GPU produces MANY raw firings
    // (the unanchored DFA re-accepts along each 40-char body) that must dedup to
    // exactly the per-chunk finding set the SIMD path produces.
    let toks = [
        "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",
        "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",
        "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",
    ];
    let mut chunks = Vec::new();
    for (i, t) in toks.iter().enumerate() {
        assert_eq!(t.len(), 40);
        chunks.push(test_chunk(
            &format!("line0\nKEY=\"{t}\"\nline2"),
            &format!("fixtures/pat_{i}.env"),
        ));
        // Interleave over-fire bait so the GPU fires the `ghp_` prefix with no body.
        chunks.push(test_chunk(
            "comment about ghp_ tokens without any real body here",
            &format!("fixtures/bait_{i}.md"),
        ));
    }

    let simd = keys(&scanner.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu));
    let gpu = keys(&scanner.scan_chunks_with_backend(&chunks, ScanBackend::Gpu));

    let simd_tokens: std::collections::BTreeSet<&str> = simd
        .iter()
        .map(|(credential, _, _)| credential.as_str())
        .filter(|credential| toks.contains(credential))
        .collect();
    assert_eq!(
        simd_tokens.len(),
        toks.len(),
        "SIMD must find all {} distinct real PATs; got {simd:?}",
        toks.len()
    );
    assert_eq!(
        simd,
        gpu,
        "GPU≢SIMD on the repeated-secret + bait corpus.\n  only SIMD: {:?}\n  only GPU: {:?}",
        simd.difference(&gpu).collect::<Vec<_>>(),
        gpu.difference(&simd).collect::<Vec<_>>(),
    );
}

/// Zero-width interior-evasion parity — the exact recall regression the
/// validated trigger production must NOT introduce. A `ghp_` PAT split by a
/// zero-width space (`\u{200B}`) does NOT match the detector regex on RAW bytes
/// but DOES after `prepare_chunk`'s interior-control strip. The SIMD path fires
/// the `ghp_` literal on raw and finds it on the stripped text. The GPU
/// validation oracle therefore MUST run on the PREPROCESSED text (not raw bytes),
/// or it would drop the bit and silently lose the finding vs SIMD (Law 10).
///
/// This pins that the oracle domain is preprocessed: SIMD and GPU must agree, and
/// both must surface the de-obfuscated secret.
#[test]
fn gpu_equals_simd_on_zero_width_obfuscated_secret() {
    require_gpu_or_panic("gpu_equals_simd_on_zero_width_obfuscated_secret");
    let scanner = scanner();

    // ghp_ + 36 body, with a zero-width space inserted INSIDE the body. The raw
    // bytes do not contain a 40-char `ghp_[A-Za-z0-9]{36}` run; the strip removes
    // the ZWSP and reveals it.
    let body = "1234567890ABCDEFghijklmnopqrst3yckgQ"; // 36 chars, checksum-valid
    assert_eq!(body.len(), 36);
    let (head, tail) = body.split_at(10);
    let obfuscated = format!("ghp_{head}\u{200B}{tail}"); // ZWSP at offset 14
    let clean = format!("ghp_{body}");

    let chunks = vec![test_chunk(
        &format!("token = \"{obfuscated}\""),
        "fixtures/zw_obfuscated.rs",
    )];

    let simd = keys(&scanner.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu));
    let gpu = keys(&scanner.scan_chunks_with_backend(&chunks, ScanBackend::Gpu));

    // SIMD must de-obfuscate and surface the cleaned token (the engine's unicode
    // hardening contract — see the adversarial unicode_normalization suite).
    assert!(
        simd.iter().any(|(cred, _, _)| cred == &clean),
        "SIMD must surface the de-obfuscated ghp_ token {clean:?}; got {simd:?}"
    );
    // The GPU path, validating on the PREPROCESSED text, must agree exactly — no
    // silent recall loss from validating on raw bytes.
    assert_eq!(
        simd,
        gpu,
        "GPU≢SIMD on the zero-width-obfuscated secret — the validation oracle must \
         run on preprocessed text, not raw bytes.\n  only SIMD: {:?}\n  only GPU: {:?}",
        simd.difference(&gpu).collect::<Vec<_>>(),
        gpu.difference(&simd).collect::<Vec<_>>(),
    );
}
