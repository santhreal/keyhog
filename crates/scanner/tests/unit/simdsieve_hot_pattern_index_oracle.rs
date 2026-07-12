//! Adversarial totality + correctness-oracle proptest for the SIMD hot-pattern
//! slot resolver `simdsieve_prefilter::hot_pattern_index_at`.
//!
//! `hot_pattern_index_at(text, offset)` translates a SimdSieve-reported byte
//! offset into the canonical HOT_PATTERNS slot index that begins there. The
//! existing `inline_migrated::simdsieve_prefilter_inline` migration pins
//! deterministic cases (each prefix at offset 0, one mid-buffer offset, a
//! near-miss, empty input, offset==len). This suite sweeps thousands of RANDOM
//! buffers at ARBITRARY offsets — crucially including offsets PAST the end of the
//! buffer — and asserts the four invariants the hot path depends on:
//!
//!   1. TOTALITY: never panics for any `(bytes, offset)`, even `offset > len`.
//!      The offset arrives from the sieve; a stale/edge offset must degrade to
//!      `None`, never index out of bounds.
//!   2. IN-RANGE: a `Some(i)` always carries a valid table index `i < HOT_PATTERNS.len()`.
//!   3. BIDIRECTIONAL PREFIX ORACLE (Law 6, not shape):
//!        * `Some(i)` ⟹ the bytes at `offset` actually start with `HOT_PATTERNS[i]`;
//!        * `None` (when `offset` is in range) ⟹ NO slot's prefix is present there.
//!      The resolver may neither attribute an absent prefix nor miss a present one.
//!   4. FIRST-MATCH: the returned `i` is the LOWEST-indexed matching slot — the
//!      documented tie-break that decides which detector id a shared-prefix byte
//!      run is attributed to.
//!
//! Together (2)+(3)+(4) pin `hot_pattern_index_at` to EXACTLY "first slot whose
//! literal prefix sits at `offset`, else None" — its whole contract.
#![cfg(feature = "simdsieve")]

use keyhog_scanner::testing::{
    hot_pattern_index_at_standalone as hot_pattern_index_at, hot_patterns_len, hot_patterns_ref,
};
use proptest::prelude::*;

/// Assert the full slot-resolver contract for one `(bytes, offset)` observation.
/// Returns the proptest failure via `?` so both properties can reuse it.
fn assert_resolver_contract(bytes: &[u8], offset: usize) -> Result<(), TestCaseError> {
    let hot = hot_patterns_ref();
    let result = hot_pattern_index_at(bytes, offset);
    match (result, bytes.get(offset..)) {
        // offset past end (or resolver said None with offset out of range): the
        // only legal `None` when `rest` is None is the out-of-bounds guard.
        (None, None) => Ok(()),
        (None, Some(rest)) => {
            // Completeness: None in range ⟹ no prefix is present at `offset`.
            for pat in hot {
                prop_assert!(
                    !rest.starts_with(pat),
                    "resolver returned None but prefix {pat:?} is present at offset {offset}"
                );
            }
            Ok(())
        }
        (Some(i), None) => {
            // A Some with an out-of-range offset would be an OOB read escaping as
            // a bogus index — must never happen.
            Err(TestCaseError::fail(format!(
                "resolver returned Some({i}) for offset {offset} past end of {}-byte buffer",
                bytes.len()
            )))
        }
        (Some(i), Some(rest)) => {
            prop_assert!(
                i < hot.len(),
                "returned index {i} is outside the {}-slot table",
                hot.len()
            );
            // Soundness: the attributed slot's prefix is physically present.
            prop_assert!(
                rest.starts_with(hot[i]),
                "attributed slot {i} ({:?}) is not present at offset {offset}",
                hot[i]
            );
            // First-match: no earlier slot also matches here.
            for (j, pat) in hot.iter().enumerate().take(i) {
                prop_assert!(
                    !rest.starts_with(pat),
                    "earlier slot {j} ({pat:?}) matches before returned slot {i} — first-match broken"
                );
            }
            Ok(())
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// Pure-random buffers at arbitrary offsets (including `offset > len`).
    /// Exercises totality, the out-of-bounds guard, and the `None`-completeness
    /// direction of the oracle; random bytes almost never contain a real prefix,
    /// so this is dominated by the "nothing here" path — exactly where an OOB or
    /// a spurious attribution would hide.
    #[test]
    fn hot_pattern_index_at_is_total_on_arbitrary_input(
        bytes in prop::collection::vec(any::<u8>(), 0..64usize),
        offset in 0..96usize,
    ) {
        assert_resolver_contract(&bytes, offset)?;
    }

    /// Plant a real hot prefix at a known offset inside random surroundings and
    /// confirm it is attributed. Exercises the `Some` direction of the oracle and
    /// the first-match tie-break — the path pure-random input never reaches.
    #[test]
    fn hot_pattern_index_at_attributes_a_planted_prefix(
        slot in 0..hot_patterns_len(),
        head in prop::collection::vec(any::<u8>(), 0..16usize),
        tail in prop::collection::vec(any::<u8>(), 0..16usize),
    ) {
        let hot = hot_patterns_ref();
        let prefix = hot[slot];
        let mut buf = head.clone();
        buf.extend_from_slice(prefix);
        buf.extend_from_slice(&tail);
        let offset = head.len();

        // The planted prefix guarantees a hit at `offset`.
        let got = hot_pattern_index_at(&buf, offset);
        prop_assert!(
            got.is_some(),
            "planted prefix {prefix:?} at offset {offset} was not attributed"
        );
        // And the full contract holds (soundness + first-match) around the plant.
        assert_resolver_contract(&buf, offset)?;
    }
}
