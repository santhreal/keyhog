//! Integrity-hash + disclaimer-comment false-positive gates for
//! `context/false_positive.rs`, reached via the `keyhog_scanner::testing`
//! facade. Migrated out of an inline `#[cfg(test)]` block to satisfy the
//! scanner folder contract (`context_false_positive_inline_tests_in_src`).

use keyhog_scanner::testing::context::{
    has_disclaimer_comment_bytes_for_test as has_disclaimer_comment_bytes,
    hash_algo_integrity_labels_for_test,
    is_false_positive_context_for_test as is_false_positive_context,
    is_false_positive_match_context_for_test as is_false_positive_match_context,
    is_integrity_hash_bytes_for_test as is_integrity_hash_bytes,
};

#[test]
fn integrity_gate_recognizes_every_canonical_label() {
    // Each canonical integrity label (sha512-/sha384-/sha256-) must be treated
    // as false-positive SRI-body context. sha384- regressed once when this gate
    // hand-rolled a diverging subset that omitted it.
    for label in hash_algo_integrity_labels_for_test() {
        let line = format!("  \"integrity\": \"{label}YWJjZGVmZ2hpamtsbW5vcHFy\"");
        assert!(
            is_integrity_hash_bytes(line.as_bytes()),
            "integrity line with canonical label {label:?} must be FP context",
        );
    }
}

#[test]
fn integrity_gate_suppresses_sha384_via_context_entry_points() {
    let line = "  \"integrity\": \"sha384-YWJjZGVmZ2hpamtsbW5vcHFy\"";
    let lines = vec![line];
    assert!(
        is_false_positive_context(&lines, 0, None),
        "sha384- SRI line must be suppressed via is_false_positive_context",
    );
    let text = format!("{line}\n");
    let offset = text.find("sha384-").expect("fixture contains label");
    assert!(
        is_false_positive_match_context(&text, offset, None),
        "sha384- SRI body must be suppressed via is_false_positive_match_context",
    );
}

#[test]
fn disclaimer_markers_cover_powershell_and_block_comment_forms() {
    // These two markers (`<#`, `* `) live in the canonical COMMENT_MARKERS owner
    // in inference.rs; the disclaimer scan previously omitted them and reported
    // the finding anyway.
    assert!(
        has_disclaimer_comment_bytes(b"key = \"x\" <# fake key #>"),
        "PowerShell block-comment disclaimer must be recognized",
    );
    assert!(
        has_disclaimer_comment_bytes(b" * not a real secret"),
        "block-comment continuation disclaimer must be recognized",
    );
    // A bare non-comment line with the phrase must NOT trip (marker required).
    assert!(!has_disclaimer_comment_bytes(b"fake key value here"));
}

#[test]
fn disclaimer_marker_inside_a_string_literal_is_not_a_comment() {
    // A `//` that lives INSIDE an open quote is a string body, not a comment, so
    // a disclaimer phrase there must NOT suppress a real credential. This pins
    // the incremental quote-state cursor (which replaced the per-hit
    // `is_inside_ascii_quotes` rescan): `quote.is_some()` at the marker skips it.
    assert!(
        !has_disclaimer_comment_bytes(b"secret = \" // fake key inside a string \""),
        "a comment marker inside an open string literal must not be a disclaimer",
    );
    // An ESCAPED quote does not close the string, so the marker stays inside it.
    assert!(
        !has_disclaimer_comment_bytes(b"secret = \"\\\" // fake key still in string\""),
        "an escaped quote must not close the string, keeping the marker quoted",
    );
    // Control twin: the SAME marker+phrase once the string is properly closed IS
    // a real trailing comment and must suppress.
    assert!(
        has_disclaimer_comment_bytes(b"secret = \"v\" // fake key"),
        "a marker after a closed string is a real disclaimer comment",
    );
}

#[test]
fn disclaimer_scan_is_linear_on_a_dense_marker_line() {
    // Regression for the O(n²) `is_inside_ascii_quotes` rescan: a long line of
    // boundary-passing `//` markers with no disclaimer phrase used to rescan
    // `[0, start)` per marker (~quadratic). With the incremental cursor this is
    // linear; the assertion is correctness (no phrase → no suppression), and the
    // size would make the quadratic form crawl.
    let dense = b" // ".repeat(50_000); // 200 KB, ~50k boundary-passing markers
    assert!(
        !has_disclaimer_comment_bytes(&dense),
        "dense comment markers with no disclaimer phrase must not suppress",
    );
    // The same dense prefix followed by a real disclaimer still trips.
    let mut dense_hit = b" // ".repeat(10_000).to_vec();
    dense_hit.extend_from_slice(b" // fake key");
    assert!(
        has_disclaimer_comment_bytes(&dense_hit),
        "a real disclaimer after dense markers must still be found",
    );
}

#[test]
fn disclaimer_tail_is_bounded_to_its_own_line() {
    // A line comment (`//`, `#`, …) runs only to end-of-line, so a disclaimer
    // phrase on a LATER line is NOT inside an earlier line's comment. Line 1 here
    // has a `//` with an EMPTY tail; line 2 carries "fake key" but no marker.
    // Before the tail was line-bounded, line 1's `//` tail ran to end-of-buffer
    // and falsely matched "fake key" on line 2 (a cross-line false suppression).
    assert!(
        !has_disclaimer_comment_bytes(b"a = 1 //\nfake key here"),
        "a disclaimer phrase on a later line must not be attributed to an earlier \
         line's comment (the comment tail is bounded to its own line)",
    );
    // Control twin: the SAME phrase on the SAME line as the marker DOES suppress,
    // proving the bound didn't over-truncate (the tail still covers its own line).
    assert!(
        has_disclaimer_comment_bytes(b"a = 1 // fake key\nunrelated line"),
        "a disclaimer on the marker's own line must still be found",
    );
}
