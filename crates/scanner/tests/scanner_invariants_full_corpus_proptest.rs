//! Scanner invariants over the FULL production detector corpus
//! (TESTING vector 12, lane 9 (proptest, 10k+ cases)).
//!
//! The existing `property/scanner_fuzz.rs` fuzzes `CompiledScanner::scan` with
//! a SYNTHETIC 2-detector set. That proves the hot path doesn't panic for a toy
//! engine, but the real binary compiles ~900 detectors, a different literal
//! set, a different Aho-Corasick automaton, different decode/entropy fan-out.
//! A panic, slice-boundary bug, or recall-losing batch path that only manifests
//! with the full corpus would ride right past the 2-detector fuzz.
//!
//! Two properties, both over the REAL on-disk corpus compiled once via
//! `LazyLock` (the ~2–3 s build amortised across every case):
//!
//!   1. `scan_never_panics_on_arbitrary_bytes` (10_000 cases), scanning any
//!      byte string (lossy-decoded to the UTF-8 the chunk API takes, including
//!      control bytes, lone surrogates' replacement, NULs, and long high-
//!      entropy runs) must RETURN, never panic / index out of bounds / overflow.
//!      Every surfaced match must also be internally consistent: its credential
//!      is non-empty and its byte offset points at a byte inside the chunk.
//!
//!   2. `coalesced_batch_loses_no_per_chunk_finding` (2_000 cases), the
//!      production batch path (`scan_coalesced`, which adds cross-chunk boundary
//!      reassembly on top of per-chunk scanning) is a SUPERSET of the per-chunk
//!      `scan` results: every credential the per-chunk path surfaces is also
//!      surfaced by the coalesced path. A coalesced optimisation that silently
//!      DROPS a finding the slow path keeps is a recall regression invisible to
//!      a single fixed fixture (the `regression_coalesced_reassembly_parity`
//!      test pins one cross-chunk case; this pins the no-loss direction under
//!      randomised multi-chunk inputs).
//!
//! Determinism: GPU runtime policy is irrelevant here (no backend is forced;
//! the default per-chunk + coalesced CPU paths run). No network, no timing.

#[path = "support/mod.rs"]
mod support;

use std::collections::BTreeSet;
use std::sync::LazyLock;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use proptest::prelude::*;
use support::paths::detector_dir;

/// The full production scanner, compiled once. A failure to load/compile here
/// is a harness error (Law 10: loud, not a silent skip).
static SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("full detector corpus must load for the invariants proptest");
    CompiledScanner::compile(detectors).expect("full detector corpus must compile")
});

fn chunk(text: &str, path: &str, base_offset: usize) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "proptest".into(),
            path: Some(path.into()),
            base_offset,
            ..Default::default()
        },
    }
}

fn creds(matches: &[keyhog_core::RawMatch]) -> BTreeSet<String> {
    matches
        .iter()
        .map(|m| m.credential.as_ref().to_string())
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Arbitrary bytes (lossy-decoded to valid UTF-8) must never panic the
    /// scanner, and every match must be internally consistent.
    #[test]
    fn scan_never_panics_on_arbitrary_bytes(raw in prop::collection::vec(any::<u8>(), 0..2048)) {
        let text = String::from_utf8_lossy(&raw).into_owned();
        let c = chunk(&text, "fuzz.bin", 0);
        let matches = SCANNER.scan(&c);
        let chunk_len = c.data.len();
        for m in &matches {
            prop_assert!(
                !m.credential.as_ref().is_empty(),
                "a surfaced match must carry a non-empty credential"
            );
            prop_assert!(
                m.location.offset < chunk_len,
                "match offset {} must point inside chunk length {chunk_len}",
                m.location.offset
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// The coalesced batch path never loses a per-chunk finding. We build a
    /// batch of random noise chunks PLUS one DEDICATED clean chunk carrying a
    /// planted credential-sufficient secret, then assert coalesced ⊇ per-chunk
    /// by credential value. The planted secret lives in its own clean chunk (not
    /// mixed with adversarial noise) so the per-chunk path finds it
    /// deterministically, the property under test is the no-LOSS direction
    /// between the two scan paths, not the scanner's robustness to hostile
    /// context (which the dedicated suppression tests own).
    #[test]
    fn coalesced_batch_loses_no_per_chunk_finding(
        noise in prop::collection::vec("[ -~\\n]{0,256}", 0..3),
        plant_slot in 0usize..4,
    ) {
        // A valid-shape AWS access key (AKIA + 16 uppercase alnum) fires on its
        // own bytes, no companion needed.
        const PLANTED: &str = "AKIAQYLPMN5HFIQR7XYZ";
        let planted_chunk = chunk(
            &format!("AWS_ACCESS_KEY_ID = \"{PLANTED}\"\n"),
            "planted.env",
            0,
        );

        // Interleave the planted chunk among the noise chunks at a random slot.
        let mut chunks: Vec<Chunk> = noise
            .iter()
            .enumerate()
            .map(|(i, n)| chunk(n, "noise.txt", (i + 1) * 4096))
            .collect();
        let at = plant_slot.min(chunks.len());
        chunks.insert(at, planted_chunk);

        // Per-chunk findings (clear cache between scans to avoid bleed).
        SCANNER.clear_fragment_cache();
        let mut per_chunk: BTreeSet<String> = BTreeSet::new();
        for c in &chunks {
            per_chunk.extend(creds(&SCANNER.scan(c)));
        }

        SCANNER.clear_fragment_cache();
        let coalesced_results = SCANNER.scan_coalesced(&chunks);
        let coalesced: BTreeSet<String> =
            coalesced_results.iter().flatten()
                .map(|m| m.credential.as_ref().to_string())
                .collect();

        // The planted secret is in the dedicated clean chunk, so the per-chunk
        // path MUST surface it (and coalesced, a superset, must too).
        let per_chunk_has_plant = per_chunk.iter().any(|c| c.contains(PLANTED));
        prop_assert!(
            per_chunk_has_plant,
            "per-chunk scan must surface the planted AWS key from its clean chunk"
        );

        // No per-chunk credential may be missing from the coalesced result.
        let lost: Vec<&String> = per_chunk
            .iter()
            .filter(|c| !coalesced.iter().any(|cc| cc.contains(c.as_str()) || c.contains(cc.as_str())))
            .collect();
        prop_assert!(
            lost.is_empty(),
            "coalesced batch path LOST per-chunk finding(s) {lost:?} \
             (recall regression: the fast path drops what the slow path keeps)"
        );
    }
}
