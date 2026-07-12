//! Regression: the HCL identifier char-class check (`!empty && all chars are
//! alphanumeric/`_`/`-`) is owned by one `is_hcl_identifier` helper instead of
//! being inlined verbatim in three parsers, and the dedup changes no output
//! (Law 6 + DEDUP).
//!
//! `parse_variable_header`, `parse_hcl_assignment`, and `parse_heredoc_marker`
//! each rejected `name.is_empty() || !name.chars().all(<id-class>)`. Three
//! copies can drift on what an HCL identifier is. They now call one helper. By
//! De Morgan `!is_hcl_identifier(x)` equals the old reject condition exactly, so
//! every accept/reject decision is preserved.
//!
//! This pins the real extracted tuples across all three identifier paths
//! (variable block default, flat assignment, heredoc marker) plus a reject case,
//! and a source pin that the inline triple-predicate is gone.

#[test]
fn hcl_identifier_paths_extract_exact_pairs() {
    // Line 1: variable "my_key" {
    // Line 2:   default = "secret-val-0123"
    // Line 3: }
    // Line 4: (blank)
    // Line 5: api-token = "tok-abcdef-0123"
    // Line 6: (blank)
    // Line 7: config = <<EOT
    // Line 8: heredoc-secret-body
    // Line 9: EOT
    let hcl = "variable \"my_key\" {\n  default = \"secret-val-0123\"\n}\n\napi-token = \"tok-abcdef-0123\"\n\nconfig = <<EOT\nheredoc-secret-body\nEOT\n";
    let pairs = keyhog_scanner::testing::parse_hcl_tuples(hcl);

    assert_eq!(
        pairs,
        vec![
            // parse_variable_header validated "my_key"
            ("my_key".to_string(), "secret-val-0123".to_string(), 2),
            // parse_hcl_assignment validated "api-token" (the `-` is allowed)
            ("api-token".to_string(), "tok-abcdef-0123".to_string(), 5),
            // parse_heredoc_marker validated "EOT"; value anchors at the body line
            ("config".to_string(), "heredoc-secret-body".to_string(), 8),
        ],
        "all three identifier-validated HCL paths must extract their pair"
    );
}

#[test]
fn hcl_invalid_assignment_identifier_is_rejected() {
    // `bad.key` contains `.`, which is not in the HCL identifier class, so the
    // assignment is rejected and yields no pair — while a sibling valid key does.
    let hcl = "bad.key = \"should-not-extract\"\ngood_key = \"yes-extract-42\"\n";
    let pairs = keyhog_scanner::testing::parse_hcl_tuples(hcl);

    assert_eq!(
        pairs,
        vec![("good_key".to_string(), "yes-extract-42".to_string(), 2)],
        "an LHS with a non-identifier char is rejected; the valid sibling still extracts"
    );
}

#[test]
fn hcl_identifier_check_is_single_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = std::fs::read_to_string(root.join("src/structured/parsers/hcl.rs"))
        .expect("hcl parser source readable");

    assert!(
        src.contains("fn is_hcl_identifier("),
        "the single-owner identifier check must exist"
    );
    // One definition + three call sites = four references.
    let refs = src.matches("is_hcl_identifier(").count();
    assert_eq!(
        refs, 4,
        "is_hcl_identifier must be defined once and called from all three parsers"
    );
    // The inline positive id-class predicate must now live in exactly one place
    // (the helper); the three duplicates are gone.
    let inline = src
        .matches("c.is_ascii_alphanumeric() || c == '_' || c == '-'")
        .count();
    assert_eq!(
        inline, 1,
        "the identifier char-class must be inlined only inside is_hcl_identifier"
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one multi-form document; these SWEEP the flat-assignment
// path (which routes through the shared `is_hcl_identifier`) over N distinct
// entries, plus the reject direction. Contract traced to parsers/hcl.rs + the
// fixed tests: a top-level `key = "value"` with an identifier-class key
// (alnum/`_`/`-`) surfaces as (key, value, its 1-based line) in document order;
// a key carrying a non-identifier char (`.`) is rejected and yields no tuple.
// Distinct `K{i}` keys keep each line unique; `v_<rand>` quoted values carry no
// quote/escape chars. Source parsers/hcl.rs is FOREIGN-DIRTY — this round-trip
// asserts the current observable contract as a regression signal. No proptest
// before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    /// N distinct top-level `K{i} = "v_<rand>"` assignments parse to EXACTLY those
    /// (key, value, line) tuples in document order; entry i is on line i+1.
    #[test]
    fn hcl_flat_assignment_round_trips(
        vals in prop::collection::vec("[a-z0-9]{4,12}", 2..=8),
    ) {
        let mut doc = String::new();
        let mut expected: Vec<(String, String, usize)> = Vec::new();
        for (i, r) in vals.iter().enumerate() {
            let key = format!("K{i}");
            let value = format!("v_{r}");
            doc.push_str(&format!("{key} = \"{value}\"\n"));
            expected.push((key, value, i + 1));
        }
        let got = keyhog_scanner::testing::parse_hcl_tuples(&doc);
        prop_assert_eq!(got, expected);
    }

    /// A key carrying a `.` (outside the identifier char-class) is rejected by
    /// the shared `is_hcl_identifier` gate ⇒ no tuple, for any surrounding shape.
    #[test]
    fn hcl_dotted_key_assignment_is_rejected(
        a in "[a-z]{1,6}",
        b in "[a-z]{1,6}",
        val in "[a-z0-9]{4,10}",
    ) {
        let doc = format!("{a}.{b} = \"v_{val}\"\n");
        let got = keyhog_scanner::testing::parse_hcl_tuples(&doc);
        prop_assert!(got.is_empty(), "dotted (non-identifier) key must be rejected, got {got:?}");
    }
}
