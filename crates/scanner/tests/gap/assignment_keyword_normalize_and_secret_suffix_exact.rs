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
