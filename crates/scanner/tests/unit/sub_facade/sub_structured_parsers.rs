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

macro_rules! line_of {
    ($pairs:expr, $ctx:expr) => {
        $pairs.iter().find(|p| p.context == $ctx).map(|p| p.line)
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
fn env_strips_trailing_comment_after_quoted_value() {
    let text = "DB_PASS=\"p4ss # w0rd\" # rotate quarterly\n";
    let pairs = parse_env(text);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].context, "DB_PASS");
    assert_eq!(pairs[0].value, "p4ss # w0rd");
    assert_eq!(pairs[0].line, 1);
}

#[test]
fn env_strips_trailing_comment_after_single_and_backtick_quotes() {
    let text = "SINGLE='one#two' # keep literal hash\nBACKTICK=`three#four` # comment\n";
    let pairs = parse_env(text);
    assert_eq!(pairs.len(), 2);
    assert_eq!(pairs[0].context, "SINGLE");
    assert_eq!(pairs[0].value, "one#two");
    assert_eq!(pairs[1].context, "BACKTICK");
    assert_eq!(pairs[1].value, "three#four");
}

#[test]
fn env_trailing_text_after_quote_is_not_silently_normalized() {
    let text = "TOKEN=\"abc\"suffix # comment\n";
    let pairs = parse_env(text);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].context, "TOKEN");
    assert_eq!(pairs[0].value, "\"abc\"suffix");
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
fn hcl_extracts_inline_variable_default() {
    let text = "variable \"api_key\" { default = \"ghp_inlineToken1234567890\" }\n";
    let pairs = parse_hcl(text);
    assert_eq!(
        value_of!(pairs, "api_key"),
        Some("ghp_inlineToken1234567890")
    );
    assert_eq!(
        pairs
            .iter()
            .find(|pair| pair.context == "api_key")
            .map(|p| p.line),
        Some(1)
    );
}

#[test]
fn hcl_extracts_flat_tfvars_assignment() {
    let text = "api_token = \"ghp_abcdefghij0123456789\"\n";
    let pairs = parse_hcl(text);
    assert_eq!(
        value_of!(pairs, "api_token"),
        Some("ghp_abcdefghij0123456789")
    );
}

#[test]
fn hcl_flat_assignment_preserves_escaped_quotes_inside_value() {
    let text = r#"api_token = "prefix\"middle\"suffix"
"#;
    let pairs = parse_hcl(text);
    assert_eq!(
        value_of!(pairs, "api_token"),
        Some(r#"prefix\"middle\"suffix"#)
    );
}

#[test]
fn hcl_variable_default_preserves_escaped_quotes_inside_value() {
    let text = r#"variable "api_token" {
  default = "prefix\"middle\"suffix"
}
"#;
    let pairs = parse_hcl(text);
    assert_eq!(
        value_of!(pairs, "api_token"),
        Some(r#"prefix\"middle\"suffix"#)
    );
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
    assert_eq!(pairs[0].context, "tfstate-output.secret");
    assert_eq!(pairs[0].value, "ghp_abcdefghij0123456789");
}

#[test]
fn tfstate_invalid_json_yields_no_pairs() {
    assert!(parse_tfstate("{not valid json").is_empty());
}

#[test]
fn tfstate_stringifies_numeric_value() {
    let text = r#"{"outputs":{"port":{"value":12345}}}"#;
    let pairs = parse_tfstate(text);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].context, "tfstate-output.port");
    assert_eq!(pairs[0].value, "12345");
}

#[test]
fn tfstate_extracts_resource_instance_attributes_with_resource_context() {
    let text = r#"{
  "resources": [
    {
      "type": "aws_db_instance",
      "name": "main",
      "instances": [
        {
          "attributes": {
            "username": "admin",
            "password": "ghp_abcdefghij0123456789",
            "connection": {
              "private_key": "-----BEGIN PRIVATE KEY-----"
            }
          }
        }
      ]
    }
  ]
}"#;
    let pairs = parse_tfstate(text);
    assert_eq!(
        value_of!(pairs, "aws_db_instance.main.username"),
        Some("admin")
    );
    assert_eq!(
        value_of!(pairs, "aws_db_instance.main.password"),
        Some("ghp_abcdefghij0123456789")
    );
    assert_eq!(
        value_of!(pairs, "aws_db_instance.main.connection.private_key"),
        Some("-----BEGIN PRIVATE KEY-----")
    );
    assert_eq!(line_of!(pairs, "aws_db_instance.main.password"), Some(10));
    assert_eq!(
        line_of!(pairs, "aws_db_instance.main.connection.private_key"),
        Some(12)
    );
}

#[test]
fn tfstate_indexes_repeated_resource_instances() {
    let text = r#"{
  "resources": [
    {
      "type": "aws_iam_access_key",
      "name": "deploy",
      "instances": [
        {"attributes": {"secret": "first-secret"}},
        {"attributes": {"secret": "second-secret"}}
      ]
    }
  ]
}"#;
    let pairs = parse_tfstate(text);
    assert_eq!(
        value_of!(pairs, "aws_iam_access_key.deploy[0].secret"),
        Some("first-secret")
    );
    assert_eq!(
        value_of!(pairs, "aws_iam_access_key.deploy[1].secret"),
        Some("second-secret")
    );
}

#[test]
fn tfstate_uses_module_and_instance_index_key_context() {
    let text = r#"{
  "resources": [
    {
      "module": "module.database",
      "type": "aws_secretsmanager_secret_version",
      "name": "app",
      "instances": [
        {"index_key": "blue", "attributes": {"secret_string": "blue-secret"}}
      ]
    }
  ]
}"#;
    let pairs = parse_tfstate(text);
    assert_eq!(
        value_of!(
            pairs,
            "module.database.aws_secretsmanager_secret_version.app[\"blue\"].secret_string"
        ),
        Some("blue-secret")
    );
}

#[test]
fn tfstate_attribute_named_value_keeps_resource_context() {
    let text = r#"{
  "resources": [
    {
      "type": "custom_resource",
      "name": "example",
      "instances": [
        {"attributes": {"metadata": {"value": "resource-owned-secret"}}}
      ]
    }
  ]
}"#;
    let pairs = parse_tfstate(text);
    assert_eq!(
        value_of!(pairs, "custom_resource.example.metadata.value"),
        Some("resource-owned-secret")
    );
    assert_eq!(
        value_of!(pairs, "tfstate-value"),
        None,
        "resource attributes named value must not be duplicated as anonymous outputs"
    );
}

#[test]
fn tfstate_attribute_named_resources_is_not_reinterpreted_as_resource_collection() {
    let text = r#"{
  "resources": [
    {
      "type": "custom_resource",
      "name": "parent",
      "instances": [
        {
          "attributes": {
            "resources": [
              {
                "type": "fake_child",
                "name": "nested",
                "instances": [
                  {"attributes": {"secret": "nested-secret"}}
                ]
              }
            ]
          }
        }
      ]
    }
  ]
}"#;
    let pairs = parse_tfstate(text);
    assert_eq!(
        value_of!(
            pairs,
            "custom_resource.parent.resources[0].instances[0].attributes.secret"
        ),
        Some("nested-secret")
    );
    assert_eq!(
        value_of!(pairs, "fake_child.nested.secret"),
        None,
        "resource-like data inside attributes must stay under the parent attribute path"
    );
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
    assert_eq!(
        value_of!(pairs, "API_KEY"),
        Some("ghp_abcdefghij0123456789")
    );
}

#[test]
fn docker_compose_map_environment_stringifies_yaml_scalars() {
    let text = "services:\n  web:\n    environment:\n      NUMERIC_PASSWORD: 12345678901234567890\n      FEATURE_TOKEN: true\n";
    let pairs = parse_docker_compose(text);
    assert_eq!(
        value_of!(pairs, "NUMERIC_PASSWORD"),
        Some("12345678901234567890")
    );
    assert_eq!(value_of!(pairs, "FEATURE_TOKEN"), Some("true"));
}

#[test]
fn docker_compose_map_environment_prefers_value_line_when_key_repeats() {
    let text = "services:\n  web:\n    labels:\n      API_KEY: label-only\n    environment:\n      API_KEY: ghp_abcdefghij0123456789\n";
    let pairs = parse_docker_compose(text);
    let pair = pairs
        .iter()
        .find(|pair| pair.context == "API_KEY")
        .expect("environment API_KEY extracted");
    assert_eq!(pair.value, "ghp_abcdefghij0123456789");
    assert_eq!(
        pair.line, 6,
        "environment mapping line must win over an earlier duplicate key"
    );
}

#[test]
fn docker_compose_list_environment() {
    let text = "services:\n  web:\n    environment:\n      - DB_PASS=supersecret\n";
    let pairs = parse_docker_compose(text);
    assert_eq!(value_of!(pairs, "DB_PASS"), Some("supersecret"));
}

#[test]
fn docker_compose_deeply_nested_yaml_is_bounded() {
    let text = deeply_nested_yaml(140, "environment:\n  API_KEY: should_not_parse\n");
    let pairs = parse_docker_compose(&text);
    assert!(
        pairs.is_empty(),
        "deeply nested compose YAML must fail closed instead of overflowing"
    );
}

// ---------------------------------------------------------------------------
// parse_k8s_secret — base64 decode under data:
// ---------------------------------------------------------------------------

#[test]
fn k8s_secret_decodes_base64_data() {
    use base64::Engine;
    let plain = "ghp_abcdefghij0123456789";
    let encoded = base64::engine::general_purpose::STANDARD.encode(plain);
    let text = format!(
        "apiVersion: v1\nkind: Secret\ndata:\n  token: {}\n",
        encoded
    );
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
fn k8s_secret_stringdata_stringifies_yaml_scalars() {
    let text = "apiVersion: v1\nkind: Secret\nstringData:\n  numeric_password: 12345678901234567890\n  enabled_token: false\n";
    let pairs = parse_k8s_secret(text);
    assert_eq!(
        value_of!(pairs, "numeric_password"),
        Some("12345678901234567890")
    );
    assert_eq!(value_of!(pairs, "enabled_token"), Some("false"));
}

#[test]
fn k8s_secret_stringdata_prefers_value_line_when_key_repeats() {
    let text = "apiVersion: v1\nkind: Secret\nmetadata:\n  labels:\n    token: label-only\nstringData:\n  token: ghp_abcdefghij0123456789\n";
    let pairs = parse_k8s_secret(text);
    let pair = pairs
        .iter()
        .find(|pair| pair.context == "token")
        .expect("stringData token extracted");
    assert_eq!(pair.value, "ghp_abcdefghij0123456789");
    assert_eq!(
        pair.line, 7,
        "stringData mapping line must win over an earlier duplicate key"
    );
}

#[test]
fn k8s_secret_invalid_yaml_empty() {
    assert!(parse_k8s_secret("\t: : : not yaml").is_empty());
}

#[test]
fn k8s_secret_deeply_nested_yaml_is_bounded() {
    let text = deeply_nested_yaml(140, "data:\n  token: c2hvdWxkX25vdF9wYXJzZQ==\n");
    let pairs = parse_k8s_secret(&text);
    assert!(
        pairs.is_empty(),
        "deeply nested k8s Secret YAML must fail closed instead of overflowing"
    );
}

fn deeply_nested_yaml(depth: usize, leaf: &str) -> String {
    let mut text = String::new();
    for level in 0..depth {
        text.push_str(&"  ".repeat(level));
        text.push_str("node");
        text.push_str(&level.to_string());
        text.push_str(":\n");
    }
    for line in leaf.lines() {
        text.push_str(&"  ".repeat(depth));
        text.push_str(line);
        text.push('\n');
    }
    text
}
