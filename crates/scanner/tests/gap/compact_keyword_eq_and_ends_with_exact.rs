//! Gap test: the keyword-compaction equality and suffix helpers.
//!
//! `engine::phase2_generic::keywords` compacts a keyword (case-fold + drop the
//! assignment separators `_`/`-`/`.`) and then compares it two ways:
//!   * `compact_keyword_eq`: the compacted form EXACTLY equals the needle;
//!   * `compact_keyword_ends_with`: the compacted form ends with the suffix.
//!
//! These are the byte primitives the strong-key anchor is built on
//! (`is_strong_keyword_anchored_hex_key`), but they were referenced only by a
//! source-shape gate, never pinned for behavior. Pin the case-fold + separator
//! collapse, the exact-equality boundary (no leading/trailing slop), and that
//! the suffix helper is a true suffix (not a prefix or whole-string match). The
//! facades pass the real separator set so the test supplies only strings. All
//! vectors were traced against the compaction logic.

use keyhog_scanner::testing::compact_keyword_ends_with_for_test as ends_with;
use keyhog_scanner::testing::compact_keyword_eq_for_test as eq;

#[test]
fn eq_is_case_folded_and_separator_stripped() {
    assert!(eq("API_KEY", "apikey"));
    assert!(eq("api-key", "apikey"));
    assert!(eq("Api.Key", "apikey"));
    assert!(eq("apikey", "apikey"));
    assert!(eq("client-secret", "clientsecret"));
    // Multiple and interspersed separators all collapse away.
    assert!(eq("API__KEY", "apikey"));
    assert!(eq("a_p_i_k_e_y", "apikey"));
    // The strong-key exclusion path: `license_key` compacts to `licensekey`.
    assert!(eq("license_key", "licensekey"));
}

#[test]
fn eq_requires_an_exact_match_with_no_slop() {
    assert!(!eq("api_keys", "apikey")); // trailing `s`
    assert!(!eq("xapikey", "apikey")); // leading `x`
    assert!(!eq("api_key", "secret")); // different token
}

#[test]
fn ends_with_is_a_true_suffix_match() {
    assert!(ends_with("vendor_api_key", "key"));
    assert!(ends_with("db.secret", "secret"));
    assert!(ends_with("KEY", "key")); // exact-length suffix, case-folded
    assert!(ends_with("my-secret", "secret"));
    assert!(ends_with("monkey", "key")); // suffix may sit inside a longer word
}

#[test]
fn ends_with_rejects_prefix_and_oversized_suffix() {
    assert!(!ends_with("keyvault", "key")); // `key` is a PREFIX here, not a suffix
    assert!(!ends_with("api_key", "secret")); // wrong suffix
    assert!(!ends_with("key", "secretkey")); // suffix longer than the compacted keyword
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin hand-picked keyword shapes; these SWEEP both helpers
// against a byte-level compaction oracle. These are the primitives the strong-key
// anchor matches on, so a compaction/comparison drift silently mis-anchors a
// keyword (recall/precision). Driven only through the public `*_for_test`
// facades; no proptest before.

use proptest::prelude::*;

/// Independent re-derivation of the source compaction (`keywords.rs`): drop the
/// `_`/`-`/`.` separator BYTES, ASCII-lowercase the rest. Byte-level, matching
/// the helper exactly (which iterates `keyword.bytes()`).
fn compact_bytes(s: &str) -> Vec<u8> {
    s.bytes()
        .filter(|b| !matches!(b, b'_' | b'-' | b'.'))
        .map(|b| b.to_ascii_lowercase())
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// `eq(keyword, needle)` ⟺ the compacted keyword bytes EXACTLY equal the
    /// needle bytes (no leading/trailing slop). The shared `[A-Za-z0-9_.-]`
    /// keyword alphabet and lowercase `[a-z0-9]` needle yield natural hits and
    /// misses (needle is compared as-is, not re-compacted (matching the helper)).
    #[test]
    fn eq_matches_byte_level_compaction_oracle(
        keyword in r"[A-Za-z0-9_.\-]{0,16}",
        needle in "[a-z0-9]{0,12}",
    ) {
        let expected = compact_bytes(&keyword) == needle.as_bytes();
        prop_assert_eq!(eq(&keyword, &needle), expected);
    }

    /// `ends_with(keyword, suffix)` ⟺ the compacted keyword bytes end with the
    /// suffix bytes (a true suffix, never a prefix or interior match).
    #[test]
    fn ends_with_matches_byte_level_compaction_oracle(
        keyword in r"[A-Za-z0-9_.\-]{0,16}",
        suffix in "[a-z0-9]{0,12}",
    ) {
        let expected = compact_bytes(&keyword).ends_with(suffix.as_bytes());
        prop_assert_eq!(ends_with(&keyword, &suffix), expected);
    }

    /// POSITIVE PATH: a keyword always `eq`s AND `ends_with`s its OWN compaction
    /// the reflexive anchor a sort/fold regression would break. (Dropping ASCII
    /// separators from valid UTF-8 keeps it valid UTF-8, so the round-trip holds.)
    #[test]
    fn a_keyword_equals_and_ends_with_its_own_compaction(
        keyword in r"[A-Za-z0-9_.\-]{0,16}",
    ) {
        let compact = String::from_utf8(compact_bytes(&keyword)).expect("ascii-safe");
        prop_assert!(eq(&keyword, &compact));
        prop_assert!(ends_with(&keyword, &compact));
    }
}
