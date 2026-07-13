use keyhog_core::{
    contains_bytes_ignore_ascii_case, contains_ignore_ascii_case, ends_with_ignore_ascii_case,
    starts_with_ignore_ascii_case,
};

#[test]
fn ascii_ci_helpers_match_without_allocating_casefolded_strings() {
    assert!(contains_ignore_ascii_case(
        "GitHub Personal Access Token",
        "github"
    ));
    assert!(contains_ignore_ascii_case(
        "GitHub Personal Access Token",
        "PERSONAL"
    ));
    assert!(contains_ignore_ascii_case(
        "GitHub Personal Access Token",
        ""
    ));
    assert!(!contains_ignore_ascii_case("GitHub", "gitlab"));

    assert!(contains_bytes_ignore_ascii_case(
        "AWS Session Token",
        b"session"
    ));
    assert!(contains_bytes_ignore_ascii_case(
        "AWS Session Token",
        b"AWS"
    ));
    assert!(contains_bytes_ignore_ascii_case("AWS Session Token", b""));
    assert!(!contains_bytes_ignore_ascii_case("AWS", b"azure"));

    assert!(starts_with_ignore_ascii_case("OpenAI", "open"));
    assert!(!starts_with_ignore_ascii_case("OpenAI", "ai"));
}

#[test]
fn starts_with_matches_case_insensitively_and_fails_closed_on_overlong_prefix() {
    assert!(starts_with_ignore_ascii_case("Bearer xyz", "bEaRer"));
    assert!(starts_with_ignore_ascii_case("anything", ""));
    // Boundary: a prefix longer than the value cannot match (no panic, no
    // out-of-bounds slice: `get(..len)` returns None).
    assert!(!starts_with_ignore_ascii_case("ab", "abc"));
    assert!(!starts_with_ignore_ascii_case("Token", "key"));
}

#[test]
fn contains_matches_case_insensitively_with_empty_and_overlong_boundaries() {
    assert!(contains_ignore_ascii_case("X-API-KEY: v", "api-key"));
    // Empty needle is vacuously contained.
    assert!(contains_ignore_ascii_case("", ""));
    // Needle longer than the haystack windows to zero candidates → false.
    assert!(!contains_ignore_ascii_case("ab", "abc"));
    assert!(!contains_ignore_ascii_case("password", "secret"));
}

#[test]
fn ascii_fold_does_not_spuriously_match_multibyte_utf8() {
    // Adversarial: a multibyte UTF-8 char must not case-fold into an ASCII
    // needle. 'Ä' (0xC3 0x84) shares no ASCII-folded bytes with "ax".
    assert!(!contains_ignore_ascii_case("Ä", "ax"));
    assert!(!contains_bytes_ignore_ascii_case("Ä", b"ax"));
    // Bytes API folds ASCII the same way and honors the empty-needle rule.
    assert!(contains_bytes_ignore_ascii_case("AUTHORIZATION", b"author"));
    assert!(contains_bytes_ignore_ascii_case("anything", b""));
    assert!(!contains_bytes_ignore_ascii_case("ab", b"abc"));
}

// `ends_with_ignore_ascii_case`: migrated out of `src/ascii_ci.rs` inline
// tests (KH-GAP-004). Case-insensitive suffix match without allocating a
// lowercased copy; used by extension/URL classification hot paths.

#[test]
fn ends_with_exact_case() {
    assert!(ends_with_ignore_ascii_case(b"config.YAML", b".YAML"));
}

#[test]
fn ends_with_mixed_case() {
    assert!(ends_with_ignore_ascii_case(b"archive.TAR.gz", b".tar.GZ"));
}

#[test]
fn ends_with_full_string() {
    assert!(ends_with_ignore_ascii_case(b"EXAMPLE", b"example"));
}

#[test]
fn ends_with_empty_suffix_always_matches() {
    assert!(ends_with_ignore_ascii_case(b"anything", b""));
    assert!(ends_with_ignore_ascii_case(b"", b""));
}

#[test]
fn ends_with_suffix_longer_than_value() {
    assert!(!ends_with_ignore_ascii_case(b".gz", b"archive.gz"));
}

#[test]
fn ends_with_no_match() {
    assert!(!ends_with_ignore_ascii_case(b"file.json", b".yaml"));
}

#[test]
fn ends_with_prefix_only_no_match() {
    // Suffix appears at the front, not the end.
    assert!(!ends_with_ignore_ascii_case(b"yaml.file", b"yaml"));
}

#[test]
fn ends_with_from_str_bytes() {
    let path = "https://host/app.WASM";
    assert!(ends_with_ignore_ascii_case(path.as_bytes(), b".wasm"));
    assert!(!ends_with_ignore_ascii_case(path.as_bytes(), b".map"));
}
