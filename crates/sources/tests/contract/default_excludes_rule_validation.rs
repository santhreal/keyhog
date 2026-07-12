//! `default_excludes` rule-list validation contracts (`src/filesystem/filter.rs`).
//! These normalizers are the config boundary for the built-in exclude lists: a
//! malformed entry (empty, non-lowercase, control char, wrong dot/separator shape
//! for its kind, or a duplicate) must be rejected with a NAMED reason, never
//! silently accepted into the matcher. Each kind's accept shape and its tight
//! near-miss rejections are pinned here; whole-input-space invariants live in
//! `property/default_excludes_rule_validation_proptest.rs`.

use keyhog_sources::testing::{normalize_rule_list_for_test, validate_rule_value_for_test};

// ── shared rejections (apply to every kind) ──────────────────────────────────

#[test]
fn empty_entry_is_rejected_for_every_kind() {
    for kind in ["extension", "path_segment", "suffix", "filename", "infix"] {
        let err = validate_rule_value_for_test("extensions", "", kind)
            .expect_err("an empty entry must be rejected");
        assert!(err.contains("must not be empty"), "kind {kind}: {err}");
    }
}

#[test]
fn uppercase_entry_is_rejected_as_non_lowercase() {
    let err = validate_rule_value_for_test("extensions", "PNG", "extension")
        .expect_err("uppercase must be rejected");
    assert!(err.contains("must be lowercase ASCII"), "{err}");
}

#[test]
fn control_character_entry_is_rejected() {
    let err = validate_rule_value_for_test("filenames", "a\tb", "filename")
        .expect_err("a tab is a control character");
    assert!(err.contains("contains a control character"), "{err}");
}

// ── Extension: bare token, no leading dot, no path separators ─────────────────

#[test]
fn extension_accepts_a_bare_lowercase_token() {
    assert!(validate_rule_value_for_test("extensions", "png", "extension").is_ok());
    assert!(validate_rule_value_for_test("extensions", "tar.gz", "extension").is_ok());
}

#[test]
fn extension_rejects_leading_dot_and_separators() {
    for bad in [".png", "dir/png", "dir\\png"] {
        let err = validate_rule_value_for_test("extensions", bad, "extension")
            .expect_err("dotted / separator extension must be rejected");
        assert!(
            err.contains("must be an extension without dot or path separators"),
            "{bad}: {err}"
        );
    }
}

// ── PathSegment / Filename: any token, just no path separators ────────────────

#[test]
fn path_segment_and_filename_accept_dotted_tokens() {
    assert!(validate_rule_value_for_test("dirs", "node_modules", "path_segment").is_ok());
    assert!(validate_rule_value_for_test("filenames", ".env", "filename").is_ok());
}

#[test]
fn path_segment_and_filename_reject_separators() {
    for kind in ["path_segment", "filename"] {
        for bad in ["a/b", "a\\b"] {
            let err = validate_rule_value_for_test("dirs", bad, kind)
                .expect_err("separators must be rejected");
            assert!(
                err.contains("must not contain path separators"),
                "{kind} {bad}: {err}"
            );
        }
    }
}

// ── Suffix: must start with a dot, no separators ──────────────────────────────

#[test]
fn suffix_requires_leading_dot() {
    assert!(validate_rule_value_for_test("suffixes", ".min.js", "suffix").is_ok());
    let err = validate_rule_value_for_test("suffixes", "min.js", "suffix")
        .expect_err("a suffix without a leading dot must be rejected");
    assert!(err.contains("must start with dot"), "{err}");
}

// ── Infix: must start AND end with a dot, no separators ───────────────────────

#[test]
fn infix_requires_leading_and_trailing_dot() {
    assert!(validate_rule_value_for_test("infixes", ".test.", "infix").is_ok());
    for bad in [".test", "test."] {
        let err = validate_rule_value_for_test("infixes", bad, "infix")
            .expect_err("an infix missing a bounding dot must be rejected");
        assert!(
            err.contains("must start and end with a dot"),
            "{bad}: {err}"
        );
    }
}

// ── normalize_rule_list: trimming, empties, duplicates ────────────────────────

#[test]
fn normalize_rejects_an_empty_list() {
    let err = normalize_rule_list_for_test("extensions", vec![], "extension")
        .expect_err("an empty list must be rejected");
    assert!(err.contains("must contain at least one entry"), "{err}");
}

#[test]
fn normalize_trims_whitespace_then_validates() {
    let out = normalize_rule_list_for_test(
        "extensions",
        vec!["  png  ".to_string(), "\tjpg".to_string()],
        "extension",
    )
    .expect("surrounding whitespace is trimmed before validation");
    assert_eq!(out, vec!["png".to_string(), "jpg".to_string()]);
}

#[test]
fn normalize_rejects_duplicates_after_trimming() {
    let err = normalize_rule_list_for_test(
        "extensions",
        vec!["png".to_string(), " png ".to_string()],
        "extension",
    )
    .expect_err("a trim-equal duplicate must be rejected");
    assert!(err.contains("duplicate"), "{err}");
    assert!(
        err.contains("png"),
        "the reason names the offending value: {err}"
    );
}
