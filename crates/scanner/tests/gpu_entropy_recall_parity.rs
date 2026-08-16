//! GPU ↔ SIMD recall parity for the ENTROPY pass across the chunk-size and
//! trigger-state classes that the coalesced GPU path and the per-chunk SIMD path
//! gate differently.
//!
//! Backstory: the 8 MiB `--profile` run shows the GPU backend with entropy
//! `calls=0` while SimdCpu shows entropy time. That reading suggested a Law-10
//! silent recall gap (GPU skips the entropy tail for large triggered chunks).
//! It is a PROFILING ARTIFACT: the coalesced path does not wire the SCAN-tree
//! profile spans, so its entropy work is invisible there (it shows in the
//! PHASE2 per-pattern section instead). The code proves entropy parity:
//!   - TRIGGERED chunk (`scan_coalesced_phase2_with_admission`,
//!     `triggered_opt = Some`): both `> MAX_SCAN_CHUNK_BYTES` (windowed) and
//!     `<= MAX_SCAN_CHUNK_BYTES` (direct) branches reach
//!     `scan_prepared_with_triggered`, where `scan_entropy_fallback` runs
//!     UNCONDITIONALLY (feature-gated only).
//!   - NO-HIT chunk: both the coalesced GPU path (scan_coalesced.rs) and the
//!     per-chunk SIMD path (compiled_api.rs) gate the entropy tail on the SAME
//!     `should_scan_no_hit_chunk` authority, so both backends make an identical
//!     scan/skip decision for the same chunk.
//!
//! These tests are the durable regression artifact for that parity (and they
//! guard the windowed.rs `then_some`-eager-underflow fix: a confirmed-anchor
//! match in an earlier window made `pos - offset` underflow and panic in debug
//! builds, which is why the >1 MiB case used to crash before reaching the
//! parity assertion).

#[path = "support/mod.rs"]
mod support;

use keyhog_scanner::{CompiledScanner, ScanBackend};
use support::contracts::test_chunk as make_chunk;
use support::gpu_gate::{assert_gpu_not_silent_empty, require_gpu_or_panic};
use support::paths::detector_dir;

type FindingKey = (String, usize);

fn collect_creds(results: &[Vec<keyhog_core::RawMatch>]) -> std::collections::BTreeSet<FindingKey> {
    let mut set = std::collections::BTreeSet::new();
    for chunk in results {
        for m in chunk {
            set.insert((m.credential.as_ref().to_string(), m.location.offset));
        }
    }
    set
}

/// The anchored secret forces a phase-1 trigger (so the chunk is admitted to
/// phase-2 on both backends, NOT routed through the no-hit gate).
const ANCHORED: &str = "AKIAQYLPMN5HFIQR7XYA";
/// Keyword-free isolated-bare high-entropy token — no prefix, no keyword, so it
/// is caught ONLY by the entropy isolated-bare pass, never by a named detector.
/// (Same shape proven detectable by the SimdCpu entropy path in the
/// `keyword_free_scan_detects_isolated_bare_high_entropy_token` unit test.)
const ENTROPY_ONLY: &str = "Zx9Cv8Bn7Mq6Pw5Er4Ty3Ui2Op1As0DfGh";

fn compile_scanner(backend: ScanBackend) -> CompiledScanner {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("detectors directory must load");
    let mut config = keyhog_scanner::ScannerConfig::default();
    config.min_confidence = 0.0;
    CompiledScanner::compile_for_backend(detectors, backend)
        .expect("scanner compile")
        .with_config(config)
}

/// Build a chunk strictly LARGER than `MAX_SCAN_CHUNK_BYTES` (1 MiB) so the GPU
/// coalesced path routes it through `scan_windowed_with_triggered` (the windowed
/// large-chunk tail) rather than the single-shot `scan_prepared_with_triggered`.
/// This is the size class the 8 MiB benchmark exercises, where a divergence — if
/// any — between the SimdCpu per-chunk path and the GPU windowed path surfaces.
fn big_mixed_corpus() -> String {
    let filler = "fn ordinary_function() { let x = compute_value(42); }\n";
    let mut s = String::with_capacity(3 * 1024 * 1024);
    // First half of filler, then both secrets mid-chunk, then more filler — well
    // past the 1 MiB window boundary on both sides so windowing is exercised.
    while s.len() < 1536 * 1024 {
        s.push_str(filler);
    }
    s.push_str(&format!("const AWS_KEY = \"{ANCHORED}\";\n"));
    s.push_str(&format!("{ENTROPY_ONLY}\n"));
    while s.len() < 2560 * 1024 {
        s.push_str(filler);
    }
    s
}

/// TRIGGERED >1 MiB chunk: the windowed coalesced path must find the entropy-only
/// secret on BOTH backends. This is the case the profile artifact made look broken
/// and the case that exercised the windowed underflow panic.
#[test]
fn gpu_runs_entropy_fallback_for_triggered_large_chunks() {
    require_gpu_or_panic("gpu_runs_entropy_fallback_for_triggered_large_chunks");
    let simd_scanner = compile_scanner(ScanBackend::SimdCpu);
    let gpu_scanner = compile_scanner(ScanBackend::GpuWgpu);

    let chunks = vec![make_chunk(
        &big_mixed_corpus(),
        "fixtures/mixed_secrets.env",
    )];

    let simd_results = simd_scanner
        .scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu)
        .expect("selected SIMD scan succeeds");
    let simd_creds = collect_creds(&simd_results);

    // SimdCpu MUST find both: the anchored detector secret and the entropy-only one.
    assert!(
        simd_creds.iter().any(|(c, _)| c == ANCHORED),
        "SimdCpu must find the anchored secret; creds={simd_creds:?}"
    );
    assert!(
        simd_creds.iter().any(|(c, _)| c == ENTROPY_ONLY),
        "SimdCpu must find the keyword-free entropy secret via the isolated-bare pass; \
         creds={simd_creds:?}"
    );

    let gpu_results = gpu_scanner
        .scan_chunks_with_backend(&chunks, ScanBackend::GpuWgpu)
        .expect("selected WGPU scan succeeds");
    let gpu_creds = collect_creds(&gpu_results);

    assert_gpu_not_silent_empty(
        gpu_results.iter().all(|c| c.is_empty()),
        simd_creds.len(),
        "gpu_runs_entropy_fallback_for_triggered_large_chunks",
    );

    // GPU must find the SAME secrets as SimdCpu — including the entropy-only one.
    // If GPU skipped the entropy tail, the entropy secret would show in only_simd.
    if simd_creds != gpu_creds {
        let only_simd: Vec<_> = simd_creds.difference(&gpu_creds).collect();
        let only_gpu: Vec<_> = gpu_creds.difference(&simd_creds).collect();
        panic!(
            "GPU/SimdCpu entropy recall parity broken (silent GPU entropy-skip).\n  \
             SimdCpu: {} creds, GPU: {} creds\n  only in SimdCpu: {only_simd:?}\n  \
             only in GPU: {only_gpu:?}",
            simd_creds.len(),
            gpu_creds.len(),
        );
    }
}

/// NO-HIT small chunk: an entropy-only secret ALONE on a line with no anchor
/// anywhere in the chunk. The chunk carries no detector literal, so it is routed
/// through the `should_scan_no_hit_chunk` gate on BOTH backends. Because the
/// chunk is small (<= 32 KiB) and the token is an isolated-bare high-entropy
/// candidate, the gate admits it — so both backends must run entropy and BOTH
/// must find the secret. This pins the no-hit path's backend parity (the case
/// `gpu_parity.rs`'s anchored corpus cannot reach).
#[test]
fn no_hit_entropy_only_small_chunk_has_backend_parity() {
    require_gpu_or_panic("no_hit_entropy_only_small_chunk_has_backend_parity");
    let simd_scanner = compile_scanner(ScanBackend::SimdCpu);
    let gpu_scanner = compile_scanner(ScanBackend::GpuWgpu);

    // Sensitive credential path plus a lone high-entropy token. No detector
    // literal is present, and the input stays well below the small-chunk bound.
    let corpus = format!("{ENTROPY_ONLY}\n");
    assert!(
        corpus.len() <= 32 * 1024,
        "must stay in the small-chunk class"
    );

    let chunks = vec![make_chunk(&corpus, "fixtures/credentials.txt")];

    let simd_results = simd_scanner
        .scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu)
        .expect("selected SIMD scan succeeds");
    let simd_creds = collect_creds(&simd_results);
    assert!(
        simd_creds.iter().any(|(c, _)| c == ENTROPY_ONLY),
        "SimdCpu must find the entropy-only secret in a no-hit small chunk \
         (should_scan_no_hit_chunk must admit it); creds={simd_creds:?}"
    );

    let gpu_results = gpu_scanner
        .scan_chunks_with_backend(&chunks, ScanBackend::GpuWgpu)
        .expect("selected WGPU scan succeeds");
    let gpu_creds = collect_creds(&gpu_results);

    assert_gpu_not_silent_empty(
        gpu_results.iter().all(|c| c.is_empty()),
        simd_creds.len(),
        "no_hit_entropy_only_small_chunk_has_backend_parity",
    );

    assert_eq!(
        simd_creds, gpu_creds,
        "GPU and SimdCpu must agree on a no-hit entropy-only chunk \
         (same should_scan_no_hit_chunk authority); SimdCpu={simd_creds:?} GPU={gpu_creds:?}"
    );
}
