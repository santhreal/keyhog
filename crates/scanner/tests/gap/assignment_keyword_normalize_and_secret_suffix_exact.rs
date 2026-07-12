//! Gap test: the assignment-keyword normalize -> secret-suffix pipeline.
//!
//! `engine::phase2_generic::keywords` turns a detector TOML keyword or the
//! generic bridge's captured LHS into a comparable token and then decides
//! whether that token claims a credential slot:
//!
//!   * `normalize_assignment_keyword` case-folds, collapses each run of
//!     `_`/`-`/`.` to a single `_`, drops a leading/trailing separator and any
//!     unrecognized byte, and yields `None` for an empty result.
//!   * `normalized_assignment_keyword_has_secret_suffix` is true when the last
//!     `_`-delimited segment is exactly one of `key`/`secret`/`token`/
//!     `password`/`passwd`/`pwd`, OR the whole token `ends_with`
//!     `key`/`secret`/`token`/`password`.
//!
//! Only a comment in the file-gate suite referenced these; neither had a direct
//! exact-value test. The two carry a subtle asymmetry — `passwd`/`pwd` match
//! ONLY as a full segment, while `key`/`secret`/`token`/`password` also match as
//! a trailing substring — and `ends_with` is substring, not word-boundary
//! (`monkey` ends with `key`). All vectors were traced against the byte logic.

use keyhog_scanner::testing::normalize_assignment_keyword_for_test as normalize;
use keyhog_scanner::testing::normalized_assignment_keyword_has_secret_suffix_for_test as has_suffix;

#[test]
fn normalize_folds_every_separator_spelling_to_one_token() {
    // The three documented spellings collapse to the same token.
    assert_eq!(
        normalize("SEGMENT_WRITE_KEY").as_deref(),
        Some("segment_write_key")
    );
    assert_eq!(
        normalize("segment-write-key").as_deref(),
        Some("segment_write_key")
    );
    assert_eq!(
        normalize("segment.write.key").as_deref(),
        Some("segment_write_key")
    );
    assert_eq!(normalize("API_KEY").as_deref(), Some("api_key"));
    assert_eq!(normalize("MixedCase123").as_deref(), Some("mixedcase123"));
    // Mixed separators each collapse to a single `_`.
    assert_eq!(normalize("a.b-c_d").as_deref(), Some("a_b_c_d"));
}

#[test]
fn normalize_collapses_runs_trims_edges_and_drops_unknown_bytes() {
    assert_eq!(normalize("api__key").as_deref(), Some("api_key")); // run collapses
    assert_eq!(normalize("_leading").as_deref(), Some("leading")); // leading sep dropped
    assert_eq!(normalize("trailing_").as_deref(), Some("trailing")); // trailing sep popped
    assert_eq!(normalize("key name").as_deref(), Some("keyname")); // space dropped, no `_`
}

#[test]
fn normalize_yields_none_when_nothing_survives() {
    assert_eq!(normalize(""), None);
    assert_eq!(normalize("___"), None); // only separators -> empty
}

#[test]
fn secret_suffix_matches_last_segment_or_trailing_substring() {
    // Last `_`-segment in the exact set.
    assert!(has_suffix("segment_write_key"));
    assert!(has_suffix("api_secret"));
    assert!(has_suffix("auth_token"));
    assert!(has_suffix("db_password"));
    assert!(has_suffix("x_passwd"));
    assert!(has_suffix("x_pwd"));
    // No `_`: matches via the `ends_with` substring set.
    assert!(has_suffix("apikey"));
    // `ends_with` is a substring, not a word boundary.
    assert!(has_suffix("monkey"));
}

#[test]
fn secret_suffix_rejects_non_credential_keys() {
    assert!(!has_suffix("segment")); // bare service marker
    assert!(!has_suffix("service_name")); // last segment not in the set
    assert!(!has_suffix("x_pwd_extra")); // `pwd` is not the LAST segment
    assert!(!has_suffix("passwordx")); // does not end with the suffix
                                       // `passwd`/`pwd` only count as a full segment, NOT as a trailing substring.
    assert!(!has_suffix("mypasswd"));
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one example per rule; these SWEEP the whole pipeline.
// `normalize` is exercised by IMPLEMENTATION-INDEPENDENT invariants (a valid
// output is a clean snake token; Some iff an alphanumeric survives; idempotent;
// pure lowercasing on clean alphanumerics) — no mirror-oracle, so a source
// regression cannot hide behind a matching bug. `has_suffix` is exercised by
// CONSTRUCTIVE differentials that isolate the subtle asymmetry:
// `key`/`secret`/`token`/`password` match as a TRAILING substring while
// `passwd`/`pwd` match ONLY as a full `_`-delimited segment. All traced against
// engine/phase2_generic/keywords.rs. No proptest before.

use proptest::prelude::*;

/// Suffixes that match via `ends_with` (a trailing substring, not a segment).
const ENDS_WITH_FAMILY: &[&str] = &["key", "secret", "token", "password"];

/// Suffixes that match ONLY as a full `_`-delimited last segment.
const SEGMENT_ONLY_FAMILY: &[&str] = &["passwd", "pwd"];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3_000))]

    /// A produced token contains ONLY `[a-z0-9_]`, never starts/ends with `_`,
    /// never contains a doubled `__` (runs collapse), and is never longer than the
    /// input. Holds for arbitrary Unicode.
    #[test]
    fn normalize_output_is_a_clean_snake_token(keyword in "(?s).{0,40}") {
        if let Some(out) = normalize(&keyword) {
            prop_assert!(
                out.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "invalid char in {:?}",
                out
            );
            prop_assert!(
                !out.starts_with('_') && !out.ends_with('_'),
                "edge `_` in {:?}",
                out
            );
            prop_assert!(!out.contains("__"), "doubled `_` in {:?}", out);
            prop_assert!(out.len() <= keyword.len(), "grew {:?} -> {:?}", keyword, out);
        }
    }

    /// A token is produced IFF the input carries at least one ASCII alphanumeric —
    /// separators/other bytes alone normalize to nothing.
    #[test]
    fn normalize_is_some_iff_input_has_an_alphanumeric(keyword in "(?s).{0,40}") {
        let has_alnum = keyword.bytes().any(|b| b.is_ascii_alphanumeric());
        prop_assert_eq!(normalize(&keyword).is_some(), has_alnum);
    }

    /// Normalization is IDEMPOTENT: a token already in normalized form maps to
    /// itself.
    #[test]
    fn normalize_is_idempotent(keyword in "(?s).{0,40}") {
        if let Some(out) = normalize(&keyword) {
            let renormalized = normalize(&out);
            prop_assert_eq!(renormalized.as_deref(), Some(out.as_str()));
        }
    }

    /// On a separator-free alphanumeric token, normalization is EXACTLY ASCII
    /// lowercasing (nothing dropped, no `_` inserted).
    #[test]
    fn normalize_is_lowercasing_on_clean_alphanumerics(base in "[A-Za-z0-9]{1,12}") {
        let lowered = base.to_ascii_lowercase();
        let got = normalize(&base);
        prop_assert_eq!(got.as_deref(), Some(lowered.as_str()));
    }

    /// The `key`/`secret`/`token`/`password` family matches as a TRAILING
    /// substring: any token ending in one of them has a secret suffix.
    #[test]
    fn ends_with_family_always_has_a_secret_suffix(
        base in "[a-z]{0,8}",
        i in 0usize..ENDS_WITH_FAMILY.len(),
    ) {
        let token = format!("{base}{}", ENDS_WITH_FAMILY[i]);
        prop_assert!(has_suffix(&token));
    }

    /// `passwd`/`pwd` match ONLY as a full `_`-delimited last segment, NEVER as a
    /// trailing substring: `<base>_pwd` has the suffix, `<base>pwd` does not (the
    /// concatenated form ends in `wd`, distinct from every `ends_with` suffix).
    #[test]
    fn passwd_family_matches_only_as_a_full_segment(
        base in "[a-z]{1,8}",
        j in 0usize..SEGMENT_ONLY_FAMILY.len(),
    ) {
        let seg = SEGMENT_ONLY_FAMILY[j];
        let as_segment = format!("{base}_{seg}");
        let as_substring = format!("{base}{seg}");
        prop_assert!(has_suffix(&as_segment));
        prop_assert!(!has_suffix(&as_substring));
    }
}
