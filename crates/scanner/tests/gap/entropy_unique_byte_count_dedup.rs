//! unique_byte_count is the single distinct-byte-count primitive that replaced
//! three byte-identical `[false; 256]` presence loops: normalized_entropy's
//! log2(unique) denominator, confidence::penalties::char_diversity, and the ML
//! feature ml_scorer::ml_features::unique_byte_count. This pins the primitive's
//! values so the DEDUP cannot drift; char_diversity now divides this by the
//! byte length and normalized_entropy feeds it to log2, both by construction.

use keyhog_scanner::testing::confidence::unique_byte_count;

#[test]
fn unique_byte_count_counts_distinct_byte_values() {
    assert_eq!(unique_byte_count(b""), 0);
    assert_eq!(unique_byte_count(b"a"), 1);
    assert_eq!(unique_byte_count(b"aaaa"), 1);
    assert_eq!(unique_byte_count(b"abcd"), 4);
    assert_eq!(unique_byte_count(b"aabbccdd"), 4);
    assert_eq!(unique_byte_count(b"abcabcabc"), 3);
    // A 20-char AWS-style placeholder: 'A','K','I' + 'X' = 4 distinct.
    assert_eq!(unique_byte_count(b"AKIAXXXXXXXXXXXXXXXX"), 4);
    // Non-ASCII bytes are counted per-byte (UTF-8 of 'é' = 0xC3 0xA9 -> 2 bytes,
    // plus 'a' = 3 distinct byte values).
    assert_eq!(unique_byte_count("aé".as_bytes()), 3);
    // Every distinct byte value present -> 256; repeating it stays 256.
    let all_bytes: Vec<u8> = (0u16..256).map(|b| b as u8).collect();
    assert_eq!(unique_byte_count(&all_bytes), 256);
    let twice: Vec<u8> = all_bytes.iter().chain(all_bytes.iter()).copied().collect();
    assert_eq!(unique_byte_count(&twice), 256);
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors above pin representative counts; these SWEEP the primitive
// against a naive set-cardinality oracle over arbitrary bytes. `unique_byte_count`
// is the SINGLE distinct-byte owner feeding normalized_entropy's log2(unique)
// denominator, confidence char_diversity, and the ML unique-byte feature, a
// miscount shifts the entropy score and mis-surfaces candidates, so exactness is
// recall-critical. No proptest covered it before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// `unique_byte_count` MUST equal the exact cardinality of the set of distinct
    /// byte values. Checked against a naive `BTreeSet<u8>` oracle over arbitrary
    /// byte strings (lengths 0..300 so the 256-distinct saturation is exercised),
    /// plus the structural bounds `count <= min(len, 256)` and `count == 0 ⟺ empty`.
    #[test]
    fn unique_byte_count_matches_naive_set_cardinality(
        bytes in prop::collection::vec(any::<u8>(), 0..300),
    ) {
        let expected = bytes
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<u8>>()
            .len();
        let got = unique_byte_count(&bytes);
        prop_assert_eq!(got, expected);
        prop_assert!(got <= 256);
        prop_assert!(got <= bytes.len());
        prop_assert_eq!(got == 0, bytes.is_empty());
    }

    /// DEDUP IDEMPOTENCE: appending copies of the input adds no distinct byte
    /// values, so the count is invariant under duplication, the exact property
    /// the primitive's name promises (it dedups presence, it does not accumulate).
    /// A regression that summed per-occurrence instead of per-distinct-value would
    /// fail here while still passing the single-pass fixed vectors above.
    #[test]
    fn unique_byte_count_is_invariant_under_duplication(
        bytes in prop::collection::vec(any::<u8>(), 0..200),
    ) {
        let base = unique_byte_count(&bytes);
        let doubled: Vec<u8> = bytes.iter().chain(bytes.iter()).copied().collect();
        let tripled: Vec<u8> = doubled.iter().chain(bytes.iter()).copied().collect();
        prop_assert_eq!(unique_byte_count(&doubled), base);
        prop_assert_eq!(unique_byte_count(&tripled), base);
    }
}
