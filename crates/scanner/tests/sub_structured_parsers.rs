//! Standalone unit coverage for `keyhog_scanner::structured::parsers`
//! (reached via the `keyhog_scanner::testing` re-export).
//!
//! Asserts the EXACT extracted (context, value, line) triples for .env, HCL,
//! tfstate, Jupyter, docker-compose, and k8s-secret inputs — including the
//! base64 decode of k8s `data:` and quote/comment stripping in .env — never
//! `is_empty` decoration. `ExtractedPair` is `pub(crate)`, so these tests read
//! its public `.context`/`.value`/`.line` fields without naming the type.

use keyhog_scanner::testing::{
    parse_docker_compose, parse_env, parse_hcl, parse_jupyter, parse_k8s_secret, parse_tfstate,
};

/// Look up the value of the first pair whose `context` equals `ctx`. Defined as
/// a macro so it works on the `pub(crate)` `ExtractedPair` element type without
/// naming it (a generic `fn` would need to bound the type).
macro_rules! value_of {
    ($pairs:expr, $ctx:expr) => {
        $pairs
            .iter()
            .find(|p| p.context == $ctx)
            .map(|p| p.value.as_str())
    };
}

// ---------------------------------------------------------------------------
// parse_env
// ---------------------------------------------------------------------------

#[test]
fn env_extracts_bare_and_quoted_values() {
    let text = "API_KEY=ghp_abcdefghij0123456789\nDB_PASS=\"p4ss w0rd\"\n";
    let pairs = parse_env(text);
    assert_eq!(pairs.len(), 2);
    assert_eq!(pairs[0].context, "API_KEY");
    assert_eq!(pairs[0].value, "ghp_abcdefghij0123456789");
    assert_eq!(pairs[0].line, 1);
    assert_eq!(pairs[1].context, "DB_PASS");
    assert_eq!(pairs[1].value, "p4ss w0rd"); // surrounding quotes stripped
    assert_eq!(pairs[1].line, 2);
}

#[test]
fn env_strips_export_prefix_and_inline_comment() {
    let text = "export TOKEN=secretvalue # rotate me\n";
    let pairs = parse_env(text);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].context, "TOKEN");
    // export stripped from key; trailing ` # comment` stripped from unquoted value.
    assert_eq!(pairs[0].value, "secretvalue");
}

#[test]
fn env_keeps_hash_inside_quoted_value() {
    let text = "PASS=\"a#b#c\"\n";
    let pairs = parse_env(text);
    assert_eq!(pairs[0].value, "a#b#c"); // quoted -> hash preserved
}

#[test]
fn env_skips_comments_and_blank_lines() {
    let text = "# header comment\n\nKEY=val\n";
    let pairs = parse_env(text);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].context, "KEY");
    assert_eq!(pairs[0].line, 3);
}

// ---------------------------------------------------------------------------
// parse_hcl
// ---------------------------------------------------------------------------

#[test]
fn hcl_extracts_variable_default() {
    let text = "variable \"db_password\" {\n  default = \"s3cr3t-value\"\n}\n";
    let pairs = parse_hcl(text);
    assert_eq!(value_of!(pairs, "db_password"), Some("s3cr3t-value"));
}

#[test]
fn hcl_extracts_flat_tfvars_assignment() {
    let text = "api_token = \"ghp_abcdefghij0123456789\"\n";
    let pairs = parse_hcl(text);
    assert_eq!(value_of!(pairs, "api_token"), Some("ghp_abcdefghij0123456789"));
}

#[test]
fn hcl_ignores_block_header_assignments() {
    // `resource "x" "b" {` must not be parsed as an assignment, but the inner
    // flat `bucket = "my-bucket"` IS extracted.
    let text = "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"my-bucket\"\n}\n";
    let pairs = parse_hcl(text);
    assert_eq!(value_of!(pairs, "bucket"), Some("my-bucket"));
    assert_eq!(value_of!(pairs, "aws_s3_bucket"), None);
}

// ---------------------------------------------------------------------------
// parse_tfstate
// ---------------------------------------------------------------------------

#[test]
fn tfstate_extracts_value_fields() {
    let text = r#"{"outputs":{"secret":{"value":"ghp_abcdefghij0123456789"}}}"#;
    let pairs = parse_tfstate(text);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].context, "tfstate-value");
    assert_eq!(pairs[0].value, "ghp_abcdefghij0123456789");
}

#[test]
fn tfstate_invalid_json_yields_no_pairs() {
    assert!(parse_tfstate("{not valid json").is_empty());
}

#[test]
fn tfstate_stringifies_numeric_value() {
    let text = r#"{"value":12345}"#;
    let pairs = parse_tfstate(text);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].value, "12345");
}

// ---------------------------------------------------------------------------
// parse_jupyter
// ---------------------------------------------------------------------------

#[test]
fn jupyter_extracts_code_cell_source() {
    let text = r##"{"cells":[
        {"cell_type":"markdown","source":"# title"},
        {"cell_type":"code","source":"api_key = 'ghp_abcdefghij0123456789'"}
    ]}"##;
    let pairs = parse_jupyter(text);
    // Only the code cell is extracted (markdown skipped); it is cell index 1.
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].context, "jupyter-cell-1");
    assert_eq!(pairs[0].value, "api_key = 'ghp_abcdefghij0123456789'");
}

#[test]
fn jupyter_joins_array_source_lines() {
    let text = r#"{"cells":[
        {"cell_type":"code","source":["import os\n","key='secret'"]}
    ]}"#;
    let pairs = parse_jupyter(text);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].value, "import os\nkey='secret'");
}

#[test]
fn jupyter_no_cells_yields_empty() {
    assert!(parse_jupyter(r#"{"metadata":{}}"#).is_empty());
}

// ---------------------------------------------------------------------------
// parse_docker_compose
// ---------------------------------------------------------------------------

#[test]
fn docker_compose_map_environment() {
    let text = "services:\n  web:\n    environment:\n      API_KEY: ghp_abcdefghij0123456789\n";
    let pairs = parse_docker_compose(text);
    assert_eq!(value_of!(pairs, "API_KEY"), Some("ghp_abcdefghij0123456789"));
}

#[test]
fn docker_compose_list_environment() {
    let text = "services:\n  web:\n    environment:\n      - DB_PASS=supersecret\n";
    let pairs = parse_docker_compose(text);
    assert_eq!(value_of!(pairs, "DB_PASS"), Some("supersecret"));
}

// ---------------------------------------------------------------------------
// parse_k8s_secret — base64 decode under data:
// ---------------------------------------------------------------------------

#[test]
fn k8s_secret_decodes_base64_data() {
    use base64::Engine;
    let plain = "ghp_abcdefghij0123456789";
    let encoded = base64::engine::general_purpose::STANDARD.encode(plain);
    let text = format!("apiVersion: v1\nkind: Secret\ndata:\n  token: {}\n", encoded);
    let pairs = parse_k8s_secret(&text);
    // The base64 is decoded back to plaintext for scanning.
    assert_eq!(value_of!(pairs, "token"), Some(plain));
}

#[test]
fn k8s_secret_stringdata_kept_verbatim() {
    let text = "apiVersion: v1\nkind: Secret\nstringData:\n  token: ghp_abcdefghij0123456789\n";
    let pairs = parse_k8s_secret(text);
    assert_eq!(value_of!(pairs, "token"), Some("ghp_abcdefghij0123456789"));
}

#[test]
fn k8s_secret_invalid_yaml_empty() {
    assert!(parse_k8s_secret("\t: : : not yaml").is_empty());
}
