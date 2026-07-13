/// Unit tests for structured-format parsers exposed via `keyhog_scanner::testing`.
///
/// Covers: parse_env, parse_docker_compose, parse_k8s_secret, parse_tfstate,
/// parse_jupyter, correctness (known-fake key-value pairs), boundary (empty
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
    // The one real assignment is extracted with its exact key AND value...
    let foo: Vec<&_> = pairs.iter().filter(|p| p.context.contains("FOO")).collect();
    assert_eq!(
        foo.len(),
        1,
        "exactly one FOO assignment must be extracted, got pairs: {pairs:?}"
    );
    assert_eq!(
        foo[0].value.as_str(),
        "bar",
        "FOO value must be exactly `bar`, got {:?}",
        foo[0].value
    );
    // ...and the surrounding blank lines must NOT leak in as empty-context pairs
    // (the actual contract this test's name promises).
    assert!(
        pairs.iter().all(|p| !p.context.trim().is_empty()),
        "blank lines must not become extracted pairs; got {pairs:?}"
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
    let pairs = parse_env(text);
    // The actual contract: a blank right-hand side carries no secret, so the
    // parser must never pair EMPTY_KEY with a non-empty value (it must not invent
    // one). Asserting the real behaviour, not merely "doesn't panic".
    assert!(
        pairs
            .iter()
            .all(|p| !(p.context.contains("EMPTY_KEY") && !p.value.trim().is_empty())),
        "EMPTY_KEY= (blank value) must not be extracted as a non-empty secret; got {pairs:?}"
    );
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
    // Must not panic, just return empty or parse what it can
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
    // The base64 `data` value must be extracted AND decoded back to the plaintext
    // secret (not left base64-encoded, and not merely "non-empty").
    let my_key = pairs
        .iter()
        .find(|p| p.context == "my-key")
        .unwrap_or_else(|| panic!("k8s secret `data.my-key` must be extracted; got {pairs:?}"));
    assert_eq!(
        my_key.value.as_str(),
        "fake_k8s_secret_value",
        "the base64 `data` value must be decoded to plaintext, got {:?}",
        my_key.value
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
    let pairs = parse_k8s_secret(text);
    // A ConfigMap is not a Secret: its `data` is plaintext configuration, not
    // credential material, so the Secret-specific parser must extract nothing 
    // extracting a ConfigMap value would be a false-positive source.
    assert!(
        pairs.is_empty(),
        "ConfigMap (non-Secret kind) must yield no extracted secret pairs; got {pairs:?}"
    );
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
    // The sensitive `master_password` attribute must be extracted with its exact
    // value: UNCONDITIONALLY. The previous `if !pairs.is_empty()` guard made the
    // whole check vacuous: it passed even when the parser extracted nothing.
    // (The parser surfaces every attribute value as a candidate, including
    // non-sensitive ones like `cluster_identifier`: and leaves the keep/drop
    // decision to the downstream detectors + entropy screens, so we assert only
    // that the real secret is present, not that others are absent.)
    let master = pairs
        .iter()
        .find(|p| p.value.contains("fake_tf_secret_value"))
        .unwrap_or_else(|| panic!("tfstate `master_password` must be extracted; got {pairs:?}"));
    assert_eq!(
        master.value.as_str(),
        "fake_tf_secret_value",
        "master_password value must be extracted exactly, got {:?}",
        master.value
    );
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
    // The assignment inside the code cell must be extracted with its value 
    // UNCONDITIONALLY (the previous `if !pairs.is_empty()` guard passed even when
    // the parser extracted nothing).
    assert!(
        pairs
            .iter()
            .any(|p| p.value.contains("fake_notebook_secret_value")),
        "Jupyter code-cell assignment must be extracted; got {pairs:?}"
    );
}

#[test]
fn parse_jupyter_markdown_cell_not_extracted() {
    let text = r#"{
  "cells": [{
    "cell_type": "markdown",
    "source": ["token = 'should_not_be_extracted'\n"]
  }]
}"#;
    let pairs = parse_jupyter(text);
    // A markdown cell is prose, not code: the parser must NOT extract the
    // assignment-shaped text inside it (only `code` cells carry real assignments).
    // Asserting the real contract, not merely "doesn't panic".
    assert!(
        pairs
            .iter()
            .all(|p| !p.value.contains("should_not_be_extracted")),
        "markdown-cell content must not be extracted as a secret; got {pairs:?}"
    );
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

// ── Jupyter rich-output MIME coverage (secrets hide in text/html, JSON, … ) ──
//
// A display-only secret rendered as `application/json`/`text/html`/… lives in
// `output.data[<mime>]`, NOT `text/plain`. The raw notebook scan also sees the
// JSON string-array fragmentation that splits a token; the structured parser
// joins the fragments and anchors the value so context-dependent detectors fire.

/// Minimal notebook: one code cell, one `execute_result` output whose `data`
/// carries `value` under the given `mime` key. `value` must be JSON-safe (the
/// markers below are plain alphanumerics).
fn notebook_with_output_data(mime: &str, value: &str) -> String {
    format!(
        r#"{{"cells":[{{"cell_type":"code","source":[],"outputs":[{{"output_type":"execute_result","data":{{"{mime}":"{value}"}}}}]}}]}}"#
    )
}

fn extracts_value(text: &str, marker: &str) -> bool {
    parse_jupyter(text).iter().any(|p| p.value.contains(marker))
}

#[test]
fn jupyter_output_text_plain_extracted() {
    // Regression: the pre-existing text/plain path is unchanged.
    assert!(extracts_value(
        &notebook_with_output_data("text/plain", "PLAINOUTPUTVALUE0123"),
        "PLAINOUTPUTVALUE0123"
    ));
}

#[test]
fn jupyter_output_text_html_extracted() {
    assert!(extracts_value(
        &notebook_with_output_data("text/html", "SECRETHTMLVALUE0123"),
        "SECRETHTMLVALUE0123"
    ));
}

#[test]
fn jupyter_output_application_json_extracted() {
    assert!(extracts_value(
        &notebook_with_output_data("application/json", "SECRETJSONVALUE0123"),
        "SECRETJSONVALUE0123"
    ));
}

#[test]
fn jupyter_output_application_javascript_extracted() {
    assert!(extracts_value(
        &notebook_with_output_data("application/javascript", "SECRETJSVALUE0123"),
        "SECRETJSVALUE0123"
    ));
}

#[test]
fn jupyter_output_image_svg_xml_extracted() {
    // SVG is text and can embed a token in an xlink:href (must be scanned).
    assert!(extracts_value(
        &notebook_with_output_data("image/svg+xml", "SECRETSVGVALUE0123"),
        "SECRETSVGVALUE0123"
    ));
}

#[test]
fn jupyter_output_text_markdown_extracted() {
    assert!(extracts_value(
        &notebook_with_output_data("text/markdown", "SECRETMDVALUE0123"),
        "SECRETMDVALUE0123"
    ));
}

#[test]
fn jupyter_output_text_latex_extracted() {
    assert!(extracts_value(
        &notebook_with_output_data("text/latex", "SECRETLATEXVALUE0123"),
        "SECRETLATEXVALUE0123"
    ));
}

#[test]
fn jupyter_output_binary_png_not_extracted_as_text() {
    // image/png is a base64 blob handled by decode-through, not a text MIME.
    let nb = notebook_with_output_data("image/png", "PNGBINARYMARKER0123");
    assert!(
        !extracts_value(&nb, "PNGBINARYMARKER0123"),
        "binary MIME payloads must not be pulled through the text-output path"
    );
}

#[test]
fn jupyter_output_unknown_mime_not_extracted() {
    // A MIME outside the text-bearing set is the gate: not extracted here.
    let nb = notebook_with_output_data("application/vnd.custom+bin", "UNKNOWNMIMEVALUE0123");
    assert!(!extracts_value(&nb, "UNKNOWNMIMEVALUE0123"));
}

#[test]
fn jupyter_output_html_string_array_is_joined() {
    // text/html as a fragment array: the join reconstructs a token split across
    // JSON string elements (which the raw scan would see broken by `","`).
    let nb = r#"{"cells":[{"cell_type":"code","source":[],"outputs":[{"output_type":"display_data","data":{"text/html":["<a href='x?t=","SPLITHTMLVALUE0123","'>y</a>"]}}]}]}"#;
    assert!(extracts_value(nb, "SPLITHTMLVALUE0123"));
}

#[test]
fn jupyter_output_json_split_across_array_reconstructs() {
    let nb = r#"{"cells":[{"cell_type":"code","source":[],"outputs":[{"output_type":"execute_result","data":{"application/json":["{\"token\": \"","SPLITJSONVALUE0123","\"}"]}}]}]}"#;
    assert!(extracts_value(nb, "SPLITJSONVALUE0123"));
}

#[test]
fn jupyter_output_stream_text_still_extracted() {
    let nb = r#"{"cells":[{"cell_type":"code","source":[],"outputs":[{"output_type":"stream","name":"stdout","text":["printed SECRETSTREAMVALUE0123\n"]}]}]}"#;
    assert!(extracts_value(nb, "SECRETSTREAMVALUE0123"));
}

#[test]
fn jupyter_output_traceback_still_extracted() {
    let nb = r#"{"cells":[{"cell_type":"code","source":[],"outputs":[{"output_type":"error","traceback":["Traceback with SECRETTBVALUE0123 leaked\n"]}]}]}"#;
    assert!(extracts_value(nb, "SECRETTBVALUE0123"));
}

#[test]
fn jupyter_output_multiple_mime_reprs_all_extracted() {
    let nb = r#"{"cells":[{"cell_type":"code","source":[],"outputs":[{"output_type":"execute_result","data":{"text/plain":"MULTIPLAIN0123","text/html":"MULTIHTML0123","application/json":"MULTIJSON0123"}}]}]}"#;
    let pairs = parse_jupyter(nb);
    for marker in ["MULTIPLAIN0123", "MULTIHTML0123", "MULTIJSON0123"] {
        assert!(
            pairs.iter().any(|p| p.value.contains(marker)),
            "every text MIME representation must be extracted: {marker}"
        );
    }
}

#[test]
fn jupyter_output_context_names_the_mime() {
    let pairs = parse_jupyter(&notebook_with_output_data("text/html", "CTXHTMLVALUE0123"));
    assert!(
        pairs
            .iter()
            .any(|p| p.context.contains("text/html") && p.value.contains("CTXHTMLVALUE0123")),
        "the extracted pair's context must name the source MIME"
    );
}

#[test]
fn jupyter_output_empty_data_object_yields_no_output_pairs() {
    let nb = r#"{"cells":[{"cell_type":"code","source":[],"outputs":[{"output_type":"execute_result","data":{}}]}]}"#;
    // No panic; no spurious output pairs from an empty data map.
    assert!(parse_jupyter(nb)
        .iter()
        .all(|p| !p.context.contains("output")));
}

#[test]
fn jupyter_output_data_non_object_is_ignored_without_panic() {
    let nb = r#"{"cells":[{"cell_type":"code","source":[],"outputs":[{"output_type":"execute_result","data":"notanobject"}]}]}"#;
    assert!(!extracts_value(nb, "notanobject"));
}

#[test]
fn jupyter_output_whitespace_only_html_is_skipped() {
    let nb = notebook_with_output_data("text/html", "   ");
    assert!(
        parse_jupyter(&nb)
            .iter()
            .all(|p| !p.context.contains("text/html")),
        "a whitespace-only rendering must not produce an empty candidate"
    );
}

#[test]
fn jupyter_multiple_outputs_each_extracted() {
    let nb = r#"{"cells":[{"cell_type":"code","source":[],"outputs":[{"output_type":"stream","name":"stdout","text":["OUTPUTONE0123\n"]},{"output_type":"execute_result","data":{"text/html":"OUTPUTTWO0123"}}]}]}"#;
    let pairs = parse_jupyter(nb);
    assert!(pairs.iter().any(|p| p.value.contains("OUTPUTONE0123")));
    assert!(pairs.iter().any(|p| p.value.contains("OUTPUTTWO0123")));
}

#[test]
fn jupyter_source_and_output_both_extracted() {
    let nb = r#"{"cells":[{"cell_type":"code","source":["api_key = 'SOURCESECRET0123'\n"],"outputs":[{"output_type":"execute_result","data":{"application/json":"OUTPUTSECRET0123"}}]}]}"#;
    let pairs = parse_jupyter(nb);
    assert!(pairs.iter().any(|p| p.value.contains("SOURCESECRET0123")));
    assert!(pairs.iter().any(|p| p.value.contains("OUTPUTSECRET0123")));
}

#[test]
fn jupyter_all_text_bearing_mimes_are_covered() {
    // Lock the full text-bearing MIME set: one output carrying a distinct marker
    // under every supported key, all extracted.
    let nb = r#"{"cells":[{"cell_type":"code","source":[],"outputs":[{"output_type":"execute_result","data":{
        "text/plain":"COVERPLAIN0123",
        "text/html":"COVERHTML0123",
        "text/markdown":"COVERMD0123",
        "text/latex":"COVERLATEX0123",
        "application/json":"COVERJSON0123",
        "application/javascript":"COVERJS0123",
        "image/svg+xml":"COVERSVG0123"
    }}]}]}"#;
    let pairs = parse_jupyter(nb);
    for marker in [
        "COVERPLAIN0123",
        "COVERHTML0123",
        "COVERMD0123",
        "COVERLATEX0123",
        "COVERJSON0123",
        "COVERJS0123",
        "COVERSVG0123",
    ] {
        assert!(
            pairs.iter().any(|p| p.value.contains(marker)),
            "text-bearing MIME must be covered: {marker}"
        );
    }
}
