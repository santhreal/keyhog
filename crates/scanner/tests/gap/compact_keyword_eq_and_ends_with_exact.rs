//! Gap test: the keyword-compaction equality helper.
//!
//! `engine::phase2_generic::keywords` compacts a keyword (case-fold + drop the
//! assignment separators `_`/`-`/`.`) and compares whether it EXACTLY equals
//! the needle.
//!
//! Pin the case-fold + separator collapse and exact-equality boundary (no
//! leading/trailing slop) used by encoded-text anchor matching.

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

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin hand-picked keyword shapes; this sweeps equality against
// a byte-level compaction oracle.

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

    /// POSITIVE PATH: a keyword always `eq`s its OWN compaction, the reflexive
    /// anchor a sort/fold regression would break.
    #[test]
    fn a_keyword_equals_and_ends_with_its_own_compaction(
        keyword in r"[A-Za-z0-9_.\-]{0,16}",
    ) {
        let compact = String::from_utf8(compact_bytes(&keyword)).expect("ascii-safe");
        prop_assert!(eq(&keyword, &compact));
    }
}
