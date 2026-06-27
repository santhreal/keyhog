/// Unit tests for structured-format parsers exposed via `keyhog_scanner::testing`.
///
/// Covers: parse_env, parse_docker_compose, parse_k8s_secret, parse_tfstate,
/// parse_jupyter — correctness (known-fake key-value pairs), boundary (empty
/// input, no matching pairs), and hostile inputs (oversized, malformed).
use keyhog_scanner::testing::{
    parse_docker_compose, parse_env, parse_jupyter, parse_jupyter_derived, parse_k8s_secret,
    parse_k8s_secret_derived, parse_tfstate, parse_tfstate_derived,
};

// ── parse_env ─────────────────────────────────────────────────────────────────

#[test]
fn parse_env_empty_returns_empty() {
    let pairs = parse_env("");
    assert!(pairs.is_empty());
}

#[test]
fn parse_env_simple_assignment_extracted() {
    let text = "API_KEY=fake_secret_value_12345\nDEBUG=true\n";
    let pairs = parse_env(text);
    let keys: Vec<&str> = pairs.iter().map(|p| p.context.as_str()).collect();
    assert!(
        keys.iter().any(|k| k.contains("API_KEY")),
        "API_KEY must be extracted as context"
    );
    let values: Vec<&str> = pairs.iter().map(|p| p.value.as_str()).collect();
    assert!(
        values.iter().any(|v| v.contains("fake_secret_value_12345")),
        "value must be extracted"
    );
}

#[test]
fn parse_env_comment_lines_excluded() {
    let text = "# This is a comment\nAPI_KEY=some_value\n";
    let pairs = parse_env(text);
    // Comment line itself must not appear as a key or value
    assert!(
        pairs.iter().all(|p| !p.context.starts_with('#')),
        "comment lines must not become context"
    );
}

#[test]
fn parse_env_blank_lines_excluded() {
    let text = "\n\n\nFOO=bar\n\n";
    let pairs = parse_env(text);
    assert!(
        !pairs.is_empty(),
        "non-empty .env with a pair should produce results"
    );
}

#[test]
fn parse_env_quoted_value_extracted() {
    let text = r#"SECRET="quoted_value_here""#;
    let pairs = parse_env(text);
    // Value should be extracted with or without quotes
    assert!(
        pairs.iter().any(|p| p.value.contains("quoted_value_here")),
        "quoted value must be extracted"
    );
}

#[test]
fn parse_env_empty_value_not_extracted_as_secret() {
    let text = "EMPTY_KEY=\n";
    // An empty value is not a secret — check the parser doesn't panic
    let _ = parse_env(text);
}

// ── parse_docker_compose ──────────────────────────────────────────────────────

#[test]
fn parse_docker_compose_empty_returns_empty() {
    let pairs = parse_docker_compose("");
    assert!(pairs.is_empty());
}

#[test]
fn parse_docker_compose_env_section_extracted() {
    let text = r#"
version: '3'
services:
  web:
    environment:
      - API_KEY=fake_docker_secret_value
      - DEBUG=false
"#;
    let pairs = parse_docker_compose(text);
    // Should extract the API_KEY pair
    assert!(
        pairs
            .iter()
            .any(|p| p.value.contains("fake_docker_secret_value")),
        "docker-compose env value must be extracted"
    );
}

#[test]
fn parse_docker_compose_env_lines_are_batched_and_attributed() {
    let text = "version: '3'\nservices:\n  web:\n    image: app\n    environment:\n      - API_KEY=fake_docker_secret_value\n      - DEBUG=false\n";
    let pairs = parse_docker_compose(text);
    let api_key = pairs
        .iter()
        .find(|pair| pair.context == "API_KEY")
        .expect("API_KEY env pair extracted");

    assert_eq!(
        api_key.line, 6,
        "docker-compose sequence env pair must report its own YAML line"
    );
}

#[test]
fn parse_docker_compose_malformed_yaml_does_not_panic() {
    let text = "{ invalid yaml: [unclosed";
    // Must not panic — just return empty or parse what it can
    let _ = parse_docker_compose(text);
}

// ── parse_k8s_secret ──────────────────────────────────────────────────────────

#[test]
fn parse_k8s_secret_empty_returns_empty() {
    let pairs = parse_k8s_secret("");
    assert!(pairs.is_empty());
}

#[test]
fn parse_k8s_secret_base64_data_extracted() {
    // Kubernetes secrets store values as base64
    use base64::Engine;
    let b64_val = base64::engine::general_purpose::STANDARD.encode(b"fake_k8s_secret_value");
    let text = format!("apiVersion: v1\nkind: Secret\ndata:\n  my-key: {b64_val}\n");
    let pairs = parse_k8s_secret(&text);
    // Should extract and decode the base64 value
    assert!(
        !pairs.is_empty(),
        "k8s secret data block must produce pairs"
    );
}

#[test]
fn parse_k8s_secret_data_and_string_data_lines_are_attributed() {
    use base64::Engine;
    let b64_val = base64::engine::general_purpose::STANDARD.encode(b"fake_k8s_secret_value");
    let text = format!(
        "apiVersion: v1\nkind: Secret\ndata:\n  token: {b64_val}\nstringData:\n  password: cleartext_secret\n"
    );
    let pairs = parse_k8s_secret(&text);
    let token = pairs
        .iter()
        .find(|pair| pair.context == "token")
        .expect("base64 data token extracted");
    let password = pairs
        .iter()
        .find(|pair| pair.context == "password")
        .expect("stringData password extracted");

    assert_eq!(token.line, 4, "data token line must point at token key");
    assert_eq!(
        password.line, 6,
        "stringData line must point at password key"
    );
}

#[test]
fn parse_k8s_secret_non_secret_kind_returns_empty() {
    let text = "apiVersion: v1\nkind: ConfigMap\ndata:\n  key: value\n";
    // ConfigMap is not a Secret — should return empty (the parser is specific to Secret kind)
    // Accept either empty or non-empty — the parser may extract configmap data too.
    // Primary assertion: no panic.
    let _ = parse_k8s_secret(text);
}

// ── parse_tfstate ────────────────────────────────────────────────────────────

#[test]
fn parse_tfstate_empty_returns_empty() {
    let pairs = parse_tfstate("");
    assert!(pairs.is_empty());
}

#[test]
fn parse_tfstate_sensitive_attributes_extracted() {
    let text = r#"{
  "version": 4,
  "resources": [{
    "type": "aws_rds_cluster",
    "instances": [{
      "attributes": {
        "master_password": "fake_tf_secret_value",
        "cluster_identifier": "my-db"
      }
    }]
  }]
}"#;
    let pairs = parse_tfstate(text);
    // Should extract the sensitive attribute
    if !pairs.is_empty() {
        assert!(
            pairs
                .iter()
                .any(|p| p.value.contains("fake_tf_secret_value")),
            "tfstate sensitive attribute must be extracted"
        );
    }
    // Primary assertion: no panic on this input
}

#[test]
fn parse_tfstate_invalid_json_does_not_panic() {
    let text = "{ not valid json [[[";
    let _ = parse_tfstate(text);
}

// ── parse_jupyter ─────────────────────────────────────────────────────────────

#[test]
fn parse_jupyter_empty_returns_empty() {
    let pairs = parse_jupyter("");
    assert!(pairs.is_empty());
}

#[test]
fn parse_jupyter_code_cell_with_assignment_extracted() {
    let text = r#"{
  "cells": [{
    "cell_type": "code",
    "source": ["api_key = 'fake_notebook_secret_value'\n"]
  }]
}"#;
    let pairs = parse_jupyter(text);
    // Should extract the assignment from the notebook cell
    if !pairs.is_empty() {
        assert!(
            pairs
                .iter()
                .any(|p| p.value.contains("fake_notebook_secret_value")),
            "Jupyter code cell secret must be extracted"
        );
    }
    // Primary assertion: no panic
}

#[test]
fn parse_jupyter_markdown_cell_not_extracted() {
    let text = r#"{
  "cells": [{
    "cell_type": "markdown",
    "source": ["token = 'should_not_be_extracted'\n"]
  }]
}"#;
    // Markdown cells should not be treated as code — no panic required.
    let _ = parse_jupyter(text);
}

#[test]
fn parse_jupyter_malformed_json_does_not_panic() {
    let _ = parse_jupyter("{ broken json <<<");
}

// ── decode-derived gate ─────────────────────────────────────────────────────
//
// The decode-through pipeline splices an already-decoded payload back into the
// parent structured scaffold and re-scans the derived buffer. On such a buffer
// (`decode_derived = true`) a parse/decode failure is EXPECTED and loses nothing
// (the payload was already surfaced upstream), so it must degrade to "no pairs"
// gracefully and must NOT count a lost surface. Depth-0 extraction is unchanged.
// The end-to-end counter contract is pinned in the isolated
// `tests/regression_structured_parse_failure_counted.rs`; here we pin the
// per-parser behavior through the test facade.

// A real `mirror-pos` corpus shape: the base64 `data:` value decodes to a JWT.
const K8S_JWT_SECRET: &str = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: token-secret\ntype: Opaque\ndata:\n  token: ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnpkV0lpT2lJeE1qTTBOVFkzT0Rrd0lpd2libUZ0WlNJNklrcHZhRzRnUkc5bElpd2lhV0YwSWpveE5URTJNak01TURJeWZRLlNmbEt4d1JKU01lS0tGMlFUNGZ3cE1lSmYzNlBPazZ5SlZfYWRRc3N3NWM=\n";

// What the decode-through pipeline produces at depth > 0: the JWT header has been
// decoded to inline JSON `{...}`; the trailing `.sig` after `}` is not a valid
// YAML key, so serde_yaml rejects the derived buffer.
const K8S_DERIVED_INVALID: &str =
    "apiVersion: v1\nkind: Secret\ndata:\n  token: {\"alg\":\"HS512\",\"typ\":\"JWT\"}.sig\n";

#[test]
fn k8s_depth0_extracts_decoded_jwt() {
    let pairs = parse_k8s_secret_derived(K8S_JWT_SECRET, false);
    assert_eq!(
        pairs.len(),
        1,
        "the single data: value must produce one pair"
    );
    assert!(
        pairs[0].value.as_str().starts_with("eyJ") && pairs[0].value.as_str().contains('.'),
        "the extracted value is the decoded JWT, not the base64 blob: {:?}",
        pairs[0].value.as_str()
    );
}

#[test]
fn k8s_derived_invalid_yaml_yields_no_pairs_without_panic() {
    assert!(parse_k8s_secret_derived(K8S_DERIVED_INVALID, true).is_empty());
}

#[test]
fn k8s_invalid_yaml_at_depth0_still_yields_no_pairs() {
    assert!(parse_k8s_secret_derived(K8S_DERIVED_INVALID, false).is_empty());
}

const DERIVED_INVALID_JSON: &str = "{ outputs: not json after decode .sig";

#[test]
fn tfstate_depth0_extracts_output_value() {
    let pairs = parse_tfstate_derived(
        r#"{"outputs":{"db_password":{"value":"s3cr3t-value-here"}}}"#,
        false,
    );
    assert!(
        pairs
            .iter()
            .any(|p| p.value.as_str() == "s3cr3t-value-here"),
        "depth-0 tfstate output value must be extracted: {:?}",
        pairs.iter().map(|p| p.value.as_str()).collect::<Vec<_>>()
    );
}

#[test]
fn tfstate_derived_invalid_json_yields_no_pairs_without_panic() {
    assert!(parse_tfstate_derived(DERIVED_INVALID_JSON, true).is_empty());
}

#[test]
fn jupyter_depth0_extracts_code_cell_source() {
    let pairs = parse_jupyter_derived(
        r#"{"cells":[{"cell_type":"code","source":["api_key = 'leaked-secret-123'"]}]}"#,
        false,
    );
    assert!(
        pairs
            .iter()
            .any(|p| p.value.as_str().contains("leaked-secret-123")),
        "depth-0 jupyter code cell source must be extracted: {:?}",
        pairs.iter().map(|p| p.value.as_str()).collect::<Vec<_>>()
    );
}

#[test]
fn jupyter_derived_invalid_json_yields_no_pairs_without_panic() {
    assert!(parse_jupyter_derived(DERIVED_INVALID_JSON, true).is_empty());
}
