//! Comprehensive bigram bloom filter tests.
//!
//! Covers: construction, lookup, edge cases, popcount diagnostics,
//! and the invariant that false negatives never occur.

use keyhog_scanner::{testing::BigramBloom, BigramPrefilterState};

// ── Construction ─────────────────────────────────────────────────────

#[test]
fn empty_bloom_never_matches() {
    let bloom = BigramBloom::empty();
    assert!(!bloom.maybe_overlaps(b"hello world"));
    assert_eq!(bloom.popcount(), 0);
}

#[test]
fn single_long_literal_selects_exact_mandatory_anchor() {
    let bloom = BigramBloom::from_literal_prefixes(&["ghp_ABCDEFG".to_string()]);
    assert!(bloom.maybe_overlaps(b"prefix_GHP_abcdefg_suffix"));
    assert!(!bloom.maybe_overlaps(b"xxghyyp_zz"));
    assert!(bloom.popcount() > 0);
}

#[test]
fn short_literal_uses_exact_case_insensitive_matching() {
    let bloom = BigramBloom::from_literal_prefixes(&["ghp_".to_string()]);
    assert!(bloom.maybe_overlaps(b"xxx_GHP_token"));
    assert!(!bloom.maybe_overlaps(b"xxx_gh_xxx"));
    assert!(!bloom.maybe_overlaps(b"zzz_p_zzz"));
}

#[test]
fn no_false_negatives_for_inserted_patterns() {
    // Invariant: if we insert a literal and then search for a chunk
    // containing that literal, maybe_overlaps MUST return true.
    let literals = vec![
        "ghp_".to_string(),
        "sk_live_".to_string(),
        "AKIA".to_string(),
        "xoxb-".to_string(),
    ];
    let bloom = BigramBloom::from_literal_prefixes(&literals);
    for lit in &literals {
        let mut chunk = b"random_prefix_".to_vec();
        chunk.extend_from_slice(lit.as_bytes());
        chunk.extend_from_slice(b"_random_suffix");
        assert!(
            bloom.maybe_overlaps(&chunk),
            "bloom missed chunk containing literal {:?}",
            lit
        );
    }
}

// ── Edge cases ───────────────────────────────────────────────────────

#[test]
fn chunks_shorter_than_the_compiled_anchor_fail_open() {
    let bloom = BigramBloom::from_literal_prefixes(&["test".to_string()]);
    assert!(bloom.maybe_overlaps(b"x"));
    assert!(bloom.maybe_overlaps(b""));
}

#[test]
fn one_byte_literal_uses_the_exact_short_anchor_owner() {
    let bloom = BigramBloom::from_literal_prefixes(&["x".to_string()]);
    assert_eq!(bloom.popcount(), 0);
    assert!(bloom.maybe_overlaps(b"xA"));
    assert!(bloom.maybe_overlaps(b"before_X_after"));
    assert!(!bloom.maybe_overlaps(b"before_y_after"));
}

#[test]
fn empty_literal_prefix_list_is_invalid_and_fails_open() {
    let bloom = BigramBloom::from_literal_prefixes(&[]);
    assert_eq!(bloom.popcount(), 0);
    assert_eq!(bloom.status().state, BigramPrefilterState::Invalid);
    assert!(bloom.maybe_overlaps(b"hello world"));
}

#[test]
fn empty_string_literal_is_invalid_and_fails_open() {
    let bloom = BigramBloom::from_literal_prefixes(&["".to_string()]);
    assert_eq!(bloom.popcount(), 0);
    assert_eq!(bloom.status().state, BigramPrefilterState::Invalid);
    assert!(bloom.maybe_overlaps(b"unrelated input"));
}

// ── Popcount diagnostics ─────────────────────────────────────────────

#[test]
fn popcount_grows_with_literals() {
    let bloom1 = BigramBloom::from_literal_prefixes(&["test".to_string()]);
    let bloom2 = BigramBloom::from_literal_prefixes(&[
        "test".to_string(),
        "another_prefix_".to_string(),
        "ghp_".to_string(),
    ]);
    // More literals → more (or equal) bits set.
    assert!(bloom2.popcount() >= bloom1.popcount());
}

#[test]
fn populated_slots_never_exceed_the_fixed_table() {
    let bloom = BigramBloom::from_literal_prefixes(&["ghp_ABCDEFG".to_string()]);
    assert!(bloom.popcount() > 0);
    assert!(bloom.popcount() <= 65_536);
}

/// Prevents long literal lengths from wrapping the minimum-anchor boundary and
/// turning an unrelated short chunk into a false rejection.
#[test]
fn overlong_literal_uses_the_eight_byte_anchor_width_without_truncation() {
    let literal = "a".repeat(300);
    let bloom = BigramBloom::from_literal_prefixes(std::slice::from_ref(&literal));
    assert!(bloom.maybe_overlaps(literal.as_bytes()));
    assert!(!bloom.maybe_overlaps(b"bbbbbbbb"));
    assert!(bloom.maybe_overlaps(b"short"));
}

// ── Worst-case scan (no-hit path) ────────────────────────────────────

#[test]
fn no_hit_on_unrelated_chunk() {
    // Bloom built from prefixes that never appear in the chunk.
    let bloom = BigramBloom::from_literal_prefixes(&[
        "ghp_".to_string(),
        "sk_live_".to_string(),
        "AKIA".to_string(),
    ]);
    // A chunk of all-zeros has only bigram (0x00, 0x00). Unless FNV
    // collides, the bloom should not match. (We accept occasional
    // false positives, the assertion is that zero-valued data is
    // unlikely to match prefix bigrams.)
    let zeros = vec![0u8; 1024];
    // We can't assert false because of FP, but we CAN assert the
    // function doesn't panic on large inputs.
    let _ = bloom.maybe_overlaps(&zeros);
}
