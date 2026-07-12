//! Path / URI / filename-reference shape suppression contracts
//! (`crates/scanner/src/suppression/shape/path.rs`).
//!
//! URIs, `/`-separated paths, and config-file names carry random-looking tails
//! that trip generic high-entropy gates but are NOT secrets. Three predicates
//! recognise them; their exact accept/reject boundaries are pinned here since a
//! too-loose gate suppresses a real credential and a too-tight one floods FPs.

use keyhog_scanner::testing::{
    looks_like_filename_reference_for_test, looks_like_scheme_prefixed_uri_for_test,
    looks_like_url_or_path_segment_for_test,
};
use proptest::prelude::*;

// ── scheme-prefixed URIs ─────────────────────────────────────────────────────

#[test]
fn scheme_uris_are_recognized() {
    assert!(looks_like_scheme_prefixed_uri_for_test(
        "https://example.com"
    )); // // form
    assert!(looks_like_scheme_prefixed_uri_for_test(
        "urn:isbn:0451450523"
    )); // extra colon
    assert!(looks_like_scheme_prefixed_uri_for_test(
        "custom-scheme:body"
    )); // dashed scheme
    assert!(looks_like_scheme_prefixed_uri_for_test("sha256:deadbeef")); // hash algo
    assert!(looks_like_scheme_prefixed_uri_for_test("mailto:abc")); // short all-alpha tail
}

#[test]
fn non_uris_are_rejected() {
    assert!(!looks_like_scheme_prefixed_uri_for_test("ab:c")); // colon at index 2 (< 3)
    assert!(!looks_like_scheme_prefixed_uri_for_test(
        "thisschemeistoolong:x"
    )); // colon > 15
    assert!(!looks_like_scheme_prefixed_uri_for_test("nocolonhere")); // no colon
    assert!(!looks_like_scheme_prefixed_uri_for_test("ab")); // too short
    assert!(!looks_like_scheme_prefixed_uri_for_test("1234:body")); // scheme has no letter
}

// ── /-separated paths ────────────────────────────────────────────────────────

#[test]
fn path_segments_are_recognized() {
    assert!(looks_like_url_or_path_segment_for_test("path/to/file"));
    assert!(looks_like_url_or_path_segment_for_test("a/b"));
    assert!(looks_like_url_or_path_segment_for_test("src/main.rs"));
}

#[test]
fn non_paths_are_rejected() {
    assert!(!looks_like_url_or_path_segment_for_test("nodashhere")); // no slash
    assert!(!looks_like_url_or_path_segment_for_test("/onlyone")); // 1 non-empty segment
    assert!(!looks_like_url_or_path_segment_for_test("123/456")); // no letters in segments
    assert!(!looks_like_url_or_path_segment_for_test("a b/c d")); // space breaks a segment
}

// ── config-file references ───────────────────────────────────────────────────

#[test]
fn filename_references_match_case_insensitively() {
    assert!(looks_like_filename_reference_for_test("config.yml"));
    assert!(looks_like_filename_reference_for_test("keystore.jks"));
    assert!(looks_like_filename_reference_for_test("app.PEM")); // upper-case suffix
    assert!(looks_like_filename_reference_for_test("secrets.env"));
    assert!(!looks_like_filename_reference_for_test("notes.txt")); // .txt not in the set
    assert!(!looks_like_filename_reference_for_test("noextension"));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// A scheme-URI match IMPLIES a colon at a valid scheme position (3..=15) — the
    /// gate can never fire without the structural scheme boundary.
    #[test]
    fn uri_match_implies_valid_scheme_colon(value in "[a-zA-Z0-9:/._-]{0,30}") {
        if looks_like_scheme_prefixed_uri_for_test(&value) {
            let colon = value.as_bytes().iter().position(|&b| b == b':');
            prop_assert!(colon.is_some());
            let idx = colon.unwrap();
            prop_assert!((3..=15).contains(&idx));
        }
    }

    /// A `//`-form URL (`scheme://…`, scheme 3-15 alpha) is ALWAYS recognized.
    #[test]
    fn scheme_slash_slash_is_always_a_uri(
        scheme in "[a-z]{3,12}",
        rest in "[a-zA-Z0-9./_-]{0,20}",
    ) {
        let uri = format!("{scheme}://{rest}");
        prop_assert!(looks_like_scheme_prefixed_uri_for_test(&uri));
    }

    /// A path match IMPLIES at least two non-empty `/`-separated segments.
    #[test]
    fn path_match_implies_two_plus_segments(value in "[a-zA-Z0-9/._-]{0,40}") {
        if looks_like_url_or_path_segment_for_test(&value) {
            let segs = value.split('/').filter(|s| !s.is_empty()).count();
            prop_assert!(segs >= 2);
        }
    }

    /// A value with NO slash is never a path segment.
    #[test]
    fn slashless_is_never_a_path(value in "[a-zA-Z0-9._-]{0,40}") {
        prop_assert!(!looks_like_url_or_path_segment_for_test(&value));
    }
}
