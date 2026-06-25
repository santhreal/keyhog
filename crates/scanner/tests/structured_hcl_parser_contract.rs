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
    }

    mod parser {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/structured/parsers/hcl.rs"
        ));
    }

    pub(crate) use parser::parse_hcl;
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
