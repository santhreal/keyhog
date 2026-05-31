//! Migrated from src/structured/parsers.rs

use keyhog_scanner::testing::{
    parse_docker_compose, parse_env, parse_hcl, parse_jupyter, parse_k8s_secret, parse_tfstate,
};

/// `parse_env` round-trips simple KEY=VALUE lines and tracks line
/// numbers correctly.
#[test]
fn env_basic_parses_key_value_with_line_numbers() {
    let text = "FOO=bar\nBAZ=qux\n# comment\nexport TOK=abc";
    let pairs = parse_env(text);
    assert_eq!(pairs.len(), 3);
    assert_eq!(pairs[0].context, "FOO");
    assert_eq!(pairs[0].value, "bar");
    assert_eq!(pairs[0].line, 1);
    assert_eq!(pairs[1].context, "BAZ");
    assert_eq!(pairs[1].line, 2);
    assert_eq!(pairs[2].context, "TOK");
    assert_eq!(pairs[2].value, "abc");
    assert_eq!(pairs[2].line, 4);
}

/// `parse_env` strips matching quotes.
#[test]
fn env_strips_matching_quotes() {
    let text = "DOUBLE=\"hello world\"\nSINGLE='another'";
    let pairs = parse_env(text);
    assert_eq!(pairs.len(), 2);
    assert_eq!(pairs[0].value, "hello world");
    assert_eq!(pairs[1].value, "another");
}

/// Regression: a docker-compose `environment:` sequence entry like
/// `=secretvalue` (leading `=`) used to produce an ExtractedPair
/// with an empty `context`. That's malformed compose and the empty
/// context would be useless downstream — must be skipped, matching
/// the k8s parser's empty-key policy.
#[test]
fn docker_compose_sequence_skips_empty_key_with_leading_equals() {
    let text = "\
services:
  app:
    environment:
      - FOO=bar
      - =should_be_skipped
      - BAZ=qux
";
    let pairs = parse_docker_compose(text);
    // Three entries in the YAML, but the one with the empty key
    // must be dropped — so we expect FOO and BAZ only.
    let contexts: Vec<_> = pairs.iter().map(|p| p.context.as_str()).collect();
    assert!(contexts.contains(&"FOO"));
    assert!(contexts.contains(&"BAZ"));
    assert!(
        !contexts.iter().any(|c| c.is_empty()),
        "empty-context entry must be skipped, got {contexts:?}"
    );
    assert_eq!(
        pairs.len(),
        2,
        "expected two pairs after dropping the empty-key entry"
    );
}

/// Docker-compose sequence form `FOO=` (empty value, non-empty key)
/// MUST still be preserved — env vars are legitimately allowed to
/// be set to empty.
#[test]
fn docker_compose_sequence_preserves_empty_value_with_present_key() {
    let text = "\
services:
  app:
    environment:
      - EMPTY_VAR=
      - SET_VAR=value
";
    let pairs = parse_docker_compose(text);
    let by_key: std::collections::HashMap<_, _> = pairs
        .iter()
        .map(|p| (p.context.clone(), p.value.clone()))
        .collect();
    assert_eq!(by_key.get("EMPTY_VAR"), Some(&String::new()));
    assert_eq!(by_key.get("SET_VAR"), Some(&"value".to_string()));
}

/// Regression: a Jupyter notebook code cell with `source` as an
/// array of strings (the canonical .ipynb form) used to attribute
/// every cell to line 1 because the joined source contained literal
/// `\n` while the on-disk JSON encodes them as the escape sequence
/// `\\n`. The line lookup therefore always missed. Now we anchor
/// on the first non-empty fragment, which IS present verbatim in
/// the source JSON.
#[test]
fn jupyter_array_source_attributes_to_first_fragment_line() {
    let nb = r#"{
            "cells": [
                {"cell_type": "markdown", "source": "header"},
                {"cell_type": "code", "source": ["import os\n", "secret='abc'\n"]}
            ]
        }"#;
    let pairs = parse_jupyter(nb);
    assert_eq!(pairs.len(), 1, "only the code cell should be extracted");
    let cell = &pairs[0];
    assert!(cell.value.contains("import os"));
    assert!(cell.value.contains("secret='abc'"));
    // The first fragment `"import os\n"` appears in the JSON on
    // a line >= 3, so the line attribution must not collapse to 1.
    assert!(
        cell.line >= 3,
        "expected line attribution to first fragment (>=3), got {}",
        cell.line
    );
}

/// Jupyter cell with single string source still works (string path,
/// not the array path).
#[test]
fn jupyter_string_source_extracts_code_cell() {
    let nb = r#"{
            "cells": [
                {"cell_type": "code", "source": "import os\nsecret='abc'"}
            ]
        }"#;
    let pairs = parse_jupyter(nb);
    assert_eq!(pairs.len(), 1);
    assert!(pairs[0].value.contains("secret='abc'"));
}

/// k8s Secret `data:` values are base64-decoded and surfaced with
/// their key as context.
#[test]
fn k8s_secret_decodes_data_field() {
    // base64("hunter2") = "aHVudGVyMg=="
    let text = "\
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
data:
  password: aHVudGVyMg==
  username: dXNlcg==
";
    let pairs = parse_k8s_secret(text);
    assert_eq!(pairs.len(), 2);
    let by_key: std::collections::HashMap<_, _> = pairs
        .iter()
        .map(|p| (p.context.clone(), p.value.clone()))
        .collect();
    assert_eq!(by_key.get("password"), Some(&"hunter2".to_string()));
    assert_eq!(by_key.get("username"), Some(&"user".to_string()));
}

/// Deeply-nested JSON must not stack-overflow `parse_tfstate`.
/// 5k levels of arrays is well past the natural Terraform statefile
/// depth and well past what serde_json would otherwise propagate
/// recursively into our walker.
#[test]
fn tfstate_deeply_nested_json_does_not_overflow() {
    let nested = "[".repeat(5_000) + &"]".repeat(5_000);
    let pairs = parse_tfstate(&nested);
    // Either the JSON parser rejects it OR our walker bails at the
    // depth cap. Either way: no panic, no crash, no findings.
    assert!(pairs.is_empty());
}

/// Same guard for the docker-compose path — a YAML mapping nested
/// thousands of levels deep must bail rather than stack-overflow.
#[test]
fn docker_compose_deeply_nested_yaml_does_not_overflow() {
    // Build a YAML doc with 1000 levels of nested `services:` maps.
    let mut yaml = String::new();
    let mut indent = String::new();
    for _ in 0..1000 {
        yaml.push_str(&indent);
        yaml.push_str("services:\n");
        indent.push_str("  ");
    }
    // Terminate with a leaf so the YAML parses.
    yaml.push_str(&indent);
    yaml.push_str("dummy: 1\n");
    let pairs = parse_docker_compose(&yaml);
    assert!(pairs.is_empty(), "deep nesting must yield no findings");
}

/// k8s `stringData:` values are surfaced verbatim (no base64).
#[test]
fn k8s_secret_passes_through_string_data() {
    let text = "\
apiVersion: v1
kind: Secret
stringData:
  token: my-plain-token
";
    let pairs = parse_k8s_secret(text);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].context, "token");
    assert_eq!(pairs[0].value, "my-plain-token");
}

/// Backtick-quoted env values get stripped of their wrapping quotes.
#[test]
fn env_backtick_quotes_are_stripped() {
    let text = "API_KEY=`ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1234`";
    let pairs = parse_env(text);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].context, "API_KEY");
    assert_eq!(
        pairs[0].value, "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1234",
        "backtick wrap must be removed, got {:?}",
        pairs[0].value
    );
}

/// Inline `# comment` after an unquoted value is dropped.
#[test]
fn env_inline_comment_is_stripped_for_unquoted_value() {
    let text = "DB_PASS=p4ssw0rd # rotate quarterly";
    let pairs = parse_env(text);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].value, "p4ssw0rd");
}

/// A `#` inside a quoted value is part of the literal string.
#[test]
fn env_inline_comment_preserved_inside_quotes() {
    let text = "PASSPHRASE=\"my#hard#pw # not-a-comment\"";
    let pairs = parse_env(text);
    assert_eq!(pairs.len(), 1);
    assert_eq!(
        pairs[0].value, "my#hard#pw # not-a-comment",
        "quoted body must be returned verbatim, hash and all"
    );
}

/// A `#` with no preceding whitespace is part of the unquoted value.
#[test]
fn env_hash_without_whitespace_is_not_a_comment() {
    let text = "URL_FRAG=https://example.com/foo#section";
    let pairs = parse_env(text);
    assert_eq!(pairs.len(), 1);
    assert_eq!(
        pairs[0].value, "https://example.com/foo#section",
        "hash without leading space is part of the value"
    );
}

/// Leading-`=` lines are skipped because they have no key context.
#[test]
fn env_leading_equals_skips_empty_key() {
    let text = "=orphan_value\nVALID=ok";
    let pairs = parse_env(text);
    let keys: Vec<_> = pairs.iter().map(|p| p.context.as_str()).collect();
    assert_eq!(keys, vec!["VALID"]);
}

/// HCL variable defaults emit the variable name and value pair.
#[test]
fn hcl_variable_default_extracts_pair() {
    let text = r#"variable "datadog_api_key" {
  type    = string
  default = "c1cdaa22e7c59a95d7abcfc816bac151"
}

resource "null_resource" "deploy" {}
"#;
    let pairs = parse_hcl(text);
    let dd: Vec<_> = pairs
        .iter()
        .filter(|p| p.context == "datadog_api_key")
        .collect();
    assert_eq!(
        dd.len(),
        1,
        "expected exactly one datadog_api_key pair, got pairs={:?}",
        pairs
            .iter()
            .map(|p| (&p.context, &p.value))
            .collect::<Vec<_>>()
    );
    assert_eq!(dd[0].value, "c1cdaa22e7c59a95d7abcfc816bac151");
    assert_eq!(
        dd[0].line, 3,
        "value lives on line 3 (default = ...), not the block header line"
    );
}

/// Unquoted HCL defaults must not emit synthetic credential pairs.
#[test]
fn hcl_variable_default_unquoted_is_skipped() {
    let text = r#"variable "enable_logging" {
  type    = bool
  default = true
}
"#;
    let pairs = parse_hcl(text);
    assert!(
        pairs.iter().all(|p| p.context != "enable_logging"),
        "unquoted bool default must NOT produce a pair, got {:?}",
        pairs
            .iter()
            .map(|p| (&p.context, &p.value))
            .collect::<Vec<_>>()
    );
}

/// Flat tfvars assignments are captured as context/value pairs.
#[test]
fn hcl_flat_tfvars_assignment_extracts_pair() {
    let text = r#"region          = "us-east-1"
slack_webhook   = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
"#;
    let pairs = parse_hcl(text);
    let webhook: Vec<_> = pairs
        .iter()
        .filter(|p| p.context == "slack_webhook")
        .collect();
    assert_eq!(
        webhook.len(),
        1,
        "expected one slack_webhook pair, got {:?}",
        pairs
            .iter()
            .map(|p| (&p.context, &p.value))
            .collect::<Vec<_>>()
    );
    assert!(webhook[0].value.starts_with("https://hooks.slack.com/"));
}

/// HCL block headers must not be parsed as flat assignments.
#[test]
fn hcl_resource_header_is_not_flat_assignment() {
    let text = r#"resource "aws_iam_role" "ci" {
  name = "ci-role"
}
"#;
    let pairs = parse_hcl(text);
    assert!(
        pairs.iter().all(|p| p.context != "resource"),
        "resource header must not produce a flat pair, got {:?}",
        pairs
            .iter()
            .map(|p| (&p.context, &p.value))
            .collect::<Vec<_>>()
    );
}

/// Duplicate k8s `data:` payloads are attributed to their own key lines.
#[test]
fn k8s_duplicate_encoded_values_get_distinct_lines() {
    let text = r#"apiVersion: v1
kind: Secret
metadata:
  name: dup-test
type: Opaque
data:
  primary: aGVsbG8=
  backup: aGVsbG8=
"#;
    let pairs = parse_k8s_secret(text);
    let primary = pairs
        .iter()
        .find(|p| p.context == "primary")
        .expect("primary key expected");
    let backup = pairs
        .iter()
        .find(|p| p.context == "backup")
        .expect("backup key expected");
    assert_eq!(primary.value, "hello");
    assert_eq!(backup.value, "hello");
    assert_ne!(
        primary.line, backup.line,
        "duplicate b64 payloads must land on different lines"
    );
    assert_eq!(primary.line, 7, "primary sits on line 7");
    assert_eq!(backup.line, 8, "backup sits on line 8");
}

/// A GitLab PAT base64-wrapped in `data:` decodes to plaintext.
#[test]
fn k8s_data_decodes_glpat_token() {
    use base64::Engine as _;

    let pat = format!("{}-{}", "glpat", "FczMULYzu_vDI5jQiW9I");
    let encoded = base64::engine::general_purpose::STANDARD.encode(pat.as_bytes());
    let text = format!(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: secret-key-secret\ntype: Opaque\ndata:\n  secret-key: {encoded}\n"
    );
    let pairs = parse_k8s_secret(&text);
    let secret = pairs
        .iter()
        .find(|p| p.context == "secret-key")
        .expect("secret-key pair expected");
    assert_eq!(
        secret.value, pat,
        "decoded value must equal the plaintext glpat token"
    );
}
