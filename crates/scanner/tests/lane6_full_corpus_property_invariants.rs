//! LANE 6 (property invariants over the REAL full production scanner).
//!
//! The existing full-corpus proptest (`scanner_invariants_full_corpus_proptest`)
//! pins two properties: arbitrary bytes never panic, and coalesced ⊇ per-chunk
//! (the no-LOSS direction). The toy 2-detector `property/scanner_fuzz` pins
//! idempotency and AWS-planting on a SYNTHETIC engine.
//!
//! This file fills the gaps neither covers, all against the SAME ~900-detector
//! on-disk corpus the shipped binary compiles (compiled once via `LazyLock`):
//!
//!   1. `coalesced_equals_per_chunk_for_single_chunk` (10_000 cases), for a
//!      ONE-chunk batch there is no cross-chunk seam to reassemble, so the
//!      production `scan_coalesced` MUST return EXACTLY the per-chunk `scan`
//!      result, same credentials, same detector ids, same offsets, not merely
//!      a superset. A coalesced path that ADDS phantom findings (boundary
//!      buffer over-firing, decode-through double counting) or DROPS one on the
//!      single-chunk case is a divergence the superset property cannot catch.
//!
//!   2. `scan_is_deterministic_across_two_runs` (10_000 cases), scanning the
//!      same arbitrary bytes twice through the FULL corpus yields the identical
//!      finding set, keyed by (detector_id, credential, offset). The toy fuzz
//!      proves this for 2 detectors; the real corpus has rayon fan-out, a
//!      fragment cache, ML-pending state, and decode recursion, any of which
//!      could leak nondeterminism that 2 detectors never exercise. Cache is
//!      cleared between the two runs so the property is true determinism, not a
//!      memoised replay.
//!
//!   3. `every_match_offset_indexes_a_char_boundary` (10_000 cases), beyond
//!      "offset ≤ len" (already pinned), every surfaced offset must land on a
//!      UTF-8 char boundary of the chunk text. An offset mid-codepoint is a
//!      slicing bug that panics the moment a reporter slices `&text[offset..]`.
//!
//! Determinism: no backend forced (default per-chunk + coalesced CPU paths),
//! no network, no timing assertions here (bounded-time lives in the adversarial
//! file). GPU runtime policy is irrelevant because nothing forces a GPU backend.

#[path = "support/mod.rs"]
mod support;

use std::collections::BTreeSet;
use std::sync::LazyLock;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use proptest::prelude::*;
use support::paths::detector_dir;

/// The full production scanner, compiled once. A load/compile failure here is a
/// harness error surfaced LOUDLY (Law 10), never a silent skip.
static SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("full detector corpus must load for the lane6 property invariants");
    CompiledScanner::compile(detectors).expect("full detector corpus must compile")
});

fn chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "lane6-prop".into(),
            path: Some("lane6.bin".into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

/// (detector_id, credential, offset), the stable identity of a finding,
/// order-independent so rayon fan-out reordering never flips equality.
type FindingKey = (String, String, usize);

fn keyset(matches: &[keyhog_core::RawMatch]) -> BTreeSet<FindingKey> {
    matches
        .iter()
        .map(|m| {
            (
                m.detector_id.as_ref().to_string(),
                m.credential.as_ref().to_string(),
                m.location.offset,
            )
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10_000,
        max_shrink_iters: 256,
        ..ProptestConfig::default()
    })]

    /// Single-chunk batch: coalesced == per-chunk EXACTLY. No seam to
    /// reassemble, so the two paths must agree finding-for-finding.
    #[test]
    fn coalesced_equals_per_chunk_for_single_chunk(
        raw in prop::collection::vec(any::<u8>(), 0..3072)
    ) {
        let text = String::from_utf8_lossy(&raw).into_owned();
        let c = chunk(&text);

        SCANNER.clear_fragment_cache();
        let per_chunk = keyset(&SCANNER.scan(&c));

        SCANNER.clear_fragment_cache();
        let coalesced_nested = SCANNER.scan_coalesced(std::slice::from_ref(&c));
        prop_assert_eq!(
            coalesced_nested.len(), 1,
            "scan_coalesced over a 1-chunk batch must return exactly 1 result vec, got {}",
            coalesced_nested.len()
        );
        let coalesced = keyset(&coalesced_nested[0]);

        prop_assert_eq!(
            &per_chunk, &coalesced,
            "single-chunk coalesced diverged from per-chunk.\n  only in per_chunk: {:?}\n  only in coalesced: {:?}",
            per_chunk.difference(&coalesced).collect::<Vec<_>>(),
            coalesced.difference(&per_chunk).collect::<Vec<_>>()
        );
    }

    /// Determinism: two cache-cleared scans of identical bytes are identical.
    #[test]
    fn scan_is_deterministic_across_two_runs(
        raw in prop::collection::vec(any::<u8>(), 0..3072)
    ) {
        let text = String::from_utf8_lossy(&raw).into_owned();
        let c = chunk(&text);

        SCANNER.clear_fragment_cache();
        let first = keyset(&SCANNER.scan(&c));
        SCANNER.clear_fragment_cache();
        let second = keyset(&SCANNER.scan(&c));

        prop_assert_eq!(
            &first, &second,
            "scanner nondeterministic across two runs.\n  only in run1: {:?}\n  only in run2: {:?}",
            first.difference(&second).collect::<Vec<_>>(),
            second.difference(&first).collect::<Vec<_>>()
        );
    }

    /// Every surfaced offset indexes a real UTF-8 char boundary of the chunk
    /// text (so `&text[offset..]` never panics in a reporter).
    #[test]
    fn every_match_offset_indexes_a_char_boundary(
        raw in prop::collection::vec(any::<u8>(), 0..3072)
    ) {
        let text = String::from_utf8_lossy(&raw).into_owned();
        let c = chunk(&text);
        let matches = SCANNER.scan(&c);
        let text_ref: &str = c.data.as_ref();
        for m in &matches {
            let off = m.location.offset;
            prop_assert!(
                off <= text_ref.len(),
                "offset {off} exceeds chunk len {}", text_ref.len()
            );
            prop_assert!(
                text_ref.is_char_boundary(off),
                "match offset {off} for detector {} is not a UTF-8 char boundary \
                 (slicing &text[{off}..] would panic)",
                m.detector_id.as_ref()
            );
        }
    }
}
