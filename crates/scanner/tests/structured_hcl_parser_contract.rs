//! Live HCL parser contract.
//!
//! The shipped scan path has raw entropy fallbacks that can see some Terraform
//! values even when the structured HCL extractor loses context. These tests
//! compile the production HCL parser source directly and assert exact extracted
//! context/value/line triples so parser-only regressions stay visible.

mod hcl_contract {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct ExtractedPair {
        pub context: String,
        pub value: String,
        pub line: usize,
        pub transport_decoded: bool,
    }

    mod parser {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/structured/parsers/hcl.rs"
        ));
    }

    pub(crate) use parser::parse_hcl;
    pub(crate) use parser::{strip_hcl_comments, strip_hcl_line_comment};
}

fn value_of<'a>(pairs: &'a [hcl_contract::ExtractedPair], context: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|pair| pair.context == context)
        .map(|pair| pair.value.as_str())
}

fn line_of(pairs: &[hcl_contract::ExtractedPair], context: &str) -> Option<usize> {
    pairs
        .iter()
        .find(|pair| pair.context == context)
        .map(|pair| pair.line)
}

#[test]
fn variable_block_ignores_braces_inside_strings_and_comments() {
    let text = r#"variable "database_password" {
  description = "literal } brace should not close the block"
  # literal { brace should not keep the block open
  default = "super-secret-pass"
}
"#;
    let pairs = hcl_contract::parse_hcl(text);
    assert_eq!(
        value_of(&pairs, "database_password"),
        Some("super-secret-pass")
    );
    assert_eq!(
        value_of(&pairs, "default"),
        None,
        "default line must not be reprocessed as a flat assignment"
    );
    assert_eq!(line_of(&pairs, "database_password"), Some(4));
}

#[test]
fn unquoted_variable_header_keeps_variable_context() {
    let text = r#"variable db_password {
  default = "my-db-pass"
}
"#;
    let pairs = hcl_contract::parse_hcl(text);
    assert_eq!(value_of(&pairs, "db_password"), Some("my-db-pass"));
    assert_eq!(value_of(&pairs, "default"), None);
    assert_eq!(line_of(&pairs, "db_password"), Some(2));
}

#[test]
fn assignment_comment_ending_with_brace_still_extracts() {
    let text = r#"api_key = "my-secret-key" # comment ending with {
"#;
    let pairs = hcl_contract::parse_hcl(text);
    assert_eq!(value_of(&pairs, "api_key"), Some("my-secret-key"));
    assert_eq!(line_of(&pairs, "api_key"), Some(1));
}

#[test]
fn multiline_block_comments_do_not_emit_assignments() {
    let text = r#"/*
api_key = "commented-out-secret"
*/
api_key = "live-secret"
"#;
    let pairs = hcl_contract::parse_hcl(text);
    assert_eq!(value_of(&pairs, "api_key"), Some("live-secret"));
    assert!(
        pairs
            .iter()
            .all(|pair| pair.value != "commented-out-secret"),
        "assignments inside block comments must not be extracted: {pairs:?}"
    );
    assert_eq!(line_of(&pairs, "api_key"), Some(4));
}

#[test]
fn interpolation_quotes_do_not_truncate_outer_string() {
    let text = r#"api_key = "${lookup(local.secrets, "datadog_key")}-tail"
"#;
    let pairs = hcl_contract::parse_hcl(text);
    assert_eq!(
        value_of(&pairs, "api_key"),
        Some(r#"${lookup(local.secrets, "datadog_key")}-tail"#)
    );
}

#[test]
fn variable_default_map_extracts_nested_assignment_context() {
    let text = r#"variable "api_credentials" {
  default = {
    username = "admin"
    password = "super-secret-password-123"
  }
}
"#;
    let pairs = hcl_contract::parse_hcl(text);
    assert_eq!(
        value_of(&pairs, "api_credentials.password"),
        Some("super-secret-password-123")
    );
    assert_eq!(line_of(&pairs, "api_credentials.password"), Some(4));
}

#[test]
fn variable_default_heredoc_extracts_content_line() {
    let text = r#"variable "api_key" {
  default = <<EOF
heredoc-secret-value
EOF
}
"#;
    let pairs = hcl_contract::parse_hcl(text);
    assert_eq!(value_of(&pairs, "api_key"), Some("heredoc-secret-value"));
    assert_eq!(
        line_of(&pairs, "api_key"),
        Some(3),
        "heredoc value must map to the content line, not the marker line"
    );
}

#[test]
fn inline_default_equals_without_space_extracts_variable_context() {
    let text = r#"variable "api_key" { default="nospace-secret-value" }
"#;
    let pairs = hcl_contract::parse_hcl(text);
    assert_eq!(value_of(&pairs, "api_key"), Some("nospace-secret-value"));
    assert_eq!(line_of(&pairs, "api_key"), Some(1));
}

#[test]
fn keyword_named_assignment_is_not_dropped_as_block_header() {
    let text = r#"provider = "provider-secret-value"
"#;
    let pairs = hcl_contract::parse_hcl(text);
    assert_eq!(value_of(&pairs, "provider"), Some("provider-secret-value"));
    assert_eq!(line_of(&pairs, "provider"), Some(1));
}

#[test]
fn long_heredoc_inside_default_map_does_not_end_variable_scan() {
    let heredoc_body = (0..24)
        .map(|idx| format!("certificate-line-{idx}"))
        .collect::<Vec<_>>()
        .join("\n");
    let text = format!(
        "variable \"api_credentials\" {{\n  default = {{\n    cert = <<EOF\n{heredoc_body}\nEOF\n    password = \"after-long-heredoc-secret\"\n  }}\n}}\n"
    );
    let pairs = hcl_contract::parse_hcl(&text);
    assert_eq!(
        value_of(&pairs, "api_credentials.password"),
        Some("after-long-heredoc-secret"),
        "heredoc payload lines must not consume the variable-block structural lookahead budget"
    );
    assert_eq!(
        value_of(&pairs, "password"),
        None,
        "post-heredoc map entries must keep variable default-map context"
    );
}

// --- HCL comment-stripper unification (single owner) -------------------------
//
// `strip_hcl_line_comment` was a second, hand-rolled comment parser that shared
// the `#`/`//`/quote logic with the stateful owner `strip_hcl_comments` but
// DIVERGED on `/*`: it returned `&line[..open]`, truncating the whole line at an
// inline block comment's open and silently dropping every assignment after it.
// It is now a thin single-line driver over the one owner. These lock that
// unification so the two can never re-diverge (ONE-PLACE) and that an inline
// block comment no longer hides trailing code (Law-10 recall).

/// ONE-PLACE lock: the single-line driver must produce byte-identical output to
/// the stateful owner it wraps, for every single-line input. A future edit that
/// re-forks a bespoke body into the single-line path (the exact regression that
/// caused the `/*` divergence) makes one of these inputs disagree.
#[test]
fn single_line_stripper_never_diverges_from_the_one_owner() {
    let cases = [
        r#"key = "value""#,
        "key = 1 # trailing hash",
        "key = 2 // trailing slashes",
        r#"key = "http://not-a-comment.example""#,
        r#"key = "a # b // c""#,
        "a = 1 /* mid */ b = 2",
        "/* leading */ c = 3",
        "d = 4 /* unterminated block to end of line",
        r#"e = "quote holding /* not a comment */ inside""#,
        "plain line, no comment at all",
        "",
    ];
    for case in cases {
        let mut in_block = false;
        let owner = hcl_contract::strip_hcl_comments(case, &mut in_block);
        assert_eq!(
            hcl_contract::strip_hcl_line_comment(case),
            owner,
            "single-line stripper diverged from strip_hcl_comments on {case:?}"
        );
    }
}

/// The inline `/* … */` block comment has its interior removed while the code
/// AFTER `*/` is PRESERVED. The pre-unification body truncated here, losing
/// `b = "keep"`: a silently dropped assignment.
#[test]
fn strip_hcl_line_comment_preserves_code_after_inline_block_comment() {
    let stripped = hcl_contract::strip_hcl_line_comment(r#"a = "drop" /* note */ b = "keep""#);
    assert!(
        stripped.contains(r#"b = "keep""#),
        "inline block comment truncated the line, losing trailing code: {stripped:?}"
    );
    assert!(
        !stripped.contains("note"),
        "block comment interior leaked into stripped code: {stripped:?}"
    );
}

/// Non-regression: the `#` and `//` line-comment forms still strip to end-of-line,
/// and a comment token embedded inside a quoted string is NOT treated as a comment.
#[test]
fn strip_hcl_line_comment_still_strips_line_comments_but_not_in_strings() {
    assert_eq!(
        hcl_contract::strip_hcl_line_comment("k = 1 # rotate me").trim(),
        "k = 1"
    );
    assert_eq!(
        hcl_contract::strip_hcl_line_comment("k = 2 // rotate me").trim(),
        "k = 2"
    );
    assert_eq!(
        hcl_contract::strip_hcl_line_comment(r#"url = "https://example.com/path""#).trim(),
        r#"url = "https://example.com/path""#
    );
}

/// Operator path: a flat `.tfvars` assignment whose value is followed by an
/// inline block comment must still surface the value (token is a fabricated
/// non-credential). Exercises parse_hcl → the unified stripper end to end.
#[test]
fn parse_hcl_extracts_value_before_inline_block_comment() {
    let pairs =
        hcl_contract::parse_hcl(r#"api_token = "TOKEN_abc123def456ghi789" /* rotate quarterly */"#);
    assert_eq!(
        value_of(&pairs, "api_token"),
        Some("TOKEN_abc123def456ghi789"),
        "value before an inline block comment was dropped: {pairs:?}"
    );
}

/// Operator path: a block comment that opens on one line and closes several lines
/// later must not swallow the assignment that follows it (stateful cross-line).
#[test]
fn parse_hcl_resumes_after_multiline_block_comment() {
    let text = "/* opening\n spanning\n three lines */\napi_key = \"KEY_zzz999yyy888www\"\n";
    let pairs = hcl_contract::parse_hcl(text);
    assert_eq!(
        value_of(&pairs, "api_key"),
        Some("KEY_zzz999yyy888www"),
        "assignment after a multi-line block comment was dropped: {pairs:?}"
    );
}

/// A quoted assignment value must survive an adjacent trailing line comment in
/// EITHER form (`#` or `//`): the comment stripper cuts the comment, never the
/// value. Complements the block-comment cases above.
#[test]
fn parse_hcl_keeps_value_before_trailing_line_comment() {
    for line in [
        "token = \"KEEPVAL_aa11bb22cc\" # trailing hash comment",
        "token = \"KEEPVAL_aa11bb22cc\" // trailing slash comment",
    ] {
        let pairs = hcl_contract::parse_hcl(line);
        assert_eq!(
            value_of(&pairs, "token"),
            Some("KEEPVAL_aa11bb22cc"),
            "value dropped by a trailing line comment in {line:?}: {pairs:?}"
        );
    }
}

/// Robustness fuzz for the unified comment stripper + the whole HCL parser.
mod hcl_robustness_fuzz {
    use super::hcl_contract;
    use proptest::prelude::*;

    /// Structural alphabet that stresses every lexer branch: comment markers
    /// (`#` `/` `*`), string delimiters (`"` `'` `` ` ``), the escape (`\`),
    /// assignment / heredoc / brace glyphs (`=` `<` `>` `{` `}` `-`), newline,
    /// and a little filler (identifier bytes + digits + space) so real
    /// assignment / variable / heredoc shapes can form by chance.
    const HCL_ALPHABET: &[u8] = b"#/*\"'`\\=<>{}-\n abv12";

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(3000))]

        /// `parse_hcl` must be TOTAL on adversarial structural input: it may
        /// return zero pairs, but it must never PANIC (a char-boundary slice, an
        /// out-of-range index, or an unterminated comment/quote/heredoc state
        /// machine) and never loop unboundedly. Every pair it returns must carry a
        /// 1-based line number, and the parse must be DETERMINISTIC (no hidden
        /// mutable state) (re-parsing identical bytes yields the same pair count).
        /// This sweeps thousands of interleavings of `#`, `//`, `/* */`, quotes,
        /// escapes, braces and heredoc markers through the now-single comment
        /// grammar (`strip_hcl_comments` and its single-line driver).
        #[test]
        fn parse_hcl_is_total_and_deterministic_on_structural_fuzz(
            bytes in prop::collection::vec(
                (0usize..HCL_ALPHABET.len()).prop_map(|i| HCL_ALPHABET[i]),
                0..240usize,
            ),
        ) {
            let input = String::from_utf8(bytes).expect("HCL_ALPHABET is ASCII");
            let pairs = hcl_contract::parse_hcl(&input);
            prop_assert!(
                pairs.iter().all(|p| p.line >= 1),
                "every extracted pair must carry a 1-based line number: {pairs:?}"
            );
            // Determinism: no hidden state carried across parses of identical input.
            let again = hcl_contract::parse_hcl(&input);
            prop_assert_eq!(
                again.len(),
                pairs.len(),
                "parse_hcl was not deterministic for the same input"
            );
        }
    }
}
