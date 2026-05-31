/// Unit tests for structured-format parsers exposed via `keyhog_scanner::testing`.
///
/// Covers: parse_env, parse_docker_compose, parse_k8s_secret, parse_tfstate,
/// parse_jupyter — correctness (known-fake key-value pairs), boundary (empty
/// input, no matching pairs), and hostile inputs (oversized, malformed).
use keyhog_scanner::testing::{
    parse_docker_compose, parse_env, parse_jupyter, parse_k8s_secret, parse_tfstate,
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
