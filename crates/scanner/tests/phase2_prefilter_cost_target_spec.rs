//! SWE-101 TARGET SPEC (intentionally FAILING until fully closed).
//!
//! The user's flagship issue: "a fallback must NEVER eat runtime, not
//! 0.000000001s." The combined no-candidate gate (`phase2_no_candidate_zero_work`)
//! removes the per-pattern marking work on no-candidate chunks, but the SWE-101
//! TARGET is stricter: the always-active phase-2 prefilter (`phase2:prefilter`) must
//! cost **< 1µs per chunk** end-to-end on a representative no-candidate corpus.
//!
//! This test measures the real per-chunk wall cost of the prefilter path
//! (`debug_prefilter_cost_ns`) over a large no-candidate corpus and asserts the
//! mean is below the 1µs SWE-101 target. It is EXPECTED TO BE RED until the
//! residual per-chunk cost (Hyperscan scratch fetch + automaton setup on the
//! candidate chunks, the gate AC pass, allocation) is driven under the target;
//! it tracks the gap so it cannot be silently forgotten (`*_target_spec.rs`
//! convention). Do NOT weaken the threshold to make it pass (Law 9); close the
//! cost instead.
//!
//! Run (release, the only meaningful regime for a ns-scale target; debug
//! measures-and-reports without gating):
//!   cargo test -p keyhog-scanner --features simd --release \
//!     --test phase2_prefilter_cost_target_spec -- --nocapture

mod support;
use support::paths::detector_dir;

use std::time::Instant;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

/// The SWE-101 per-chunk cost target for the always-active phase-2 prefilter.
const TARGET_NS_PER_CHUNK: f64 = 1_000.0;

/// Build N distinct no-candidate chunks (ordinary source/prose with no credential
/// prefix, keyword, or high-entropy run) so the prefilter's no-candidate path is
/// what is measured, at realistic chunk sizes.
fn no_candidate_chunks(n: usize) -> Vec<Chunk> {
    (0..n)
        .map(|i| {
            let text = format!(
                "// module {i}: ordinary configuration with no secrets whatsoever\n\
                 fn handler_{i}(input: u32) -> u32 {{ input.wrapping_mul({i}).rotate_left(7) }}\n\
                 const LABEL_{i}: &str = \"ordinary descriptive label number {i}\";\n\
                 // the quick brown fox jumps over the lazy dog, again and again\n"
            );
            Chunk {
                data: text.into(),
                metadata: ChunkMetadata {
                    source_type: "swe101-cost".into(),
                    path: Some(format!("/synthetic/mod_{i}.rs").into()),
                    base_offset: 0,
                    ..Default::default()
                },
            }
        })
        .collect()
}

#[test]
fn fb_prefilter_under_one_microsecond_per_chunk() {
    // Required test asset: fail closed rather than skip the whole cost gate.
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("load detectors from the required on-disk detector directory");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let chunks = no_candidate_chunks(20_000);

    // Warm caches (HS scratch, lazy regex, gate AC) so the timed loop measures
    // steady-state per-chunk cost, not first-touch initialization.
    for c in chunks.iter().take(256) {
        let _ = scanner.scan_chunks_with_backend(std::slice::from_ref(c), ScanBackend::SimdCpu);
    }

    let t = Instant::now();
    let mut sink = 0usize;
    for c in &chunks {
        sink += scanner
            .scan_chunks_with_backend(std::slice::from_ref(c), ScanBackend::SimdCpu)
            .iter()
            .map(Vec::len)
            .sum::<usize>();
    }
    let elapsed = t.elapsed();
    assert_eq!(sink, 0, "no-candidate corpus must produce zero findings");

    let per_chunk_ns = elapsed.as_nanos() as f64 / chunks.len() as f64;
    eprintln!(
        "SWE-101 phase2:prefilter end-to-end no-candidate cost: {per_chunk_ns:.1} ns/chunk \
         (target < {TARGET_NS_PER_CHUNK:.0} ns)"
    );

    // Debug builds run orders of magnitude slower than this ns-scale target, so
    // the absolute cost is only meaningful in `--release` (the only regime the
    // header documents). Debug measures + reports without gating; the functional
    // zero-findings assertion above still runs in every mode. In release this is
    // a RUNNING RED target-spec gate (like `target_spec/perf_10x_*`, never
    // `#[ignore]`) that turns green only when the residual per-chunk cost closes.
    if cfg!(debug_assertions) {
        return;
    }
    // NOTE: this measures the WHOLE scan path per no-candidate chunk, not the
    // isolated prefilter span, so it is a strict upper bound on `phase2:prefilter`. It
    // stays RED until the residual no-candidate per-chunk cost is under the target.
    assert!(
        per_chunk_ns < TARGET_NS_PER_CHUNK,
        "SWE-101 TARGET NOT YET MET: {per_chunk_ns:.1} ns/chunk on no-candidate input \
         exceeds the < {TARGET_NS_PER_CHUNK:.0} ns/chunk target. Close the residual \
         per-chunk cost (do NOT relax the threshold. Law 9)."
    );
}
