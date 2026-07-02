//! Regression: structured-parser recursion / DoS bounds.
//!
//! The structured preprocessor turns config formats (tfstate JSON, k8s Secret /
//! docker-compose YAML, Terraform HCL) into scannable `(context, value, line)`
//! pairs. Adversarial input can nest arbitrarily deep; the parsers guard against
//! stack exhaustion with `MAX_STRUCTURED_TRAVERSAL_DEPTH` (256) on top of serde's
//! own parse-time recursion limit, and HCL bounds its line lookahead with
//! `MAX_HEREDOC_LINES` (512). This suite pins that:
//!   * a flat / shallow doc extracts the EXACT key/value/line pair,
//!   * a doc nested within limits still surfaces the buried secret,
//!   * a doc nested beyond the recursion/parse cap terminates with NO panic and
//!     surfaces NO deeper pair (exact count 0),
//!   * malformed input yields the exact empty result,
//!   * the oversize-skip coverage-gap partition classifies decode-through vs.
//!     context-only formats exactly.
//!
//! All entry points are the plain-`pub` `keyhog_scanner::testing` integration
//! facades over the crate-internal `structured::parsers`.

use keyhog_scanner::testing;

// ---------------------------------------------------------------------------
// JSON (tfstate) — the primary recursive parser.
// ---------------------------------------------------------------------------

#[test]
fn tfstate_flat_output_extracts_exact_pair() {
    let text = r#"{"outputs":{"db_password":{"value":"tok-ABC-123"}}}"#;
    let pairs = testing::parse_tfstate_tuples(text);
    assert_eq!(
        pairs,
        vec![(
            "tfstate-output.db_password".to_string(),
            "tok-ABC-123".to_string(),
            1,
        )],
        "a flat tfstate output must surface exactly one (tfstate-output.<key>, value, line) pair"
    );
}

#[test]
fn tfstate_multiple_outputs_extract_in_btreemap_sorted_order() {
    // serde_json (no preserve_order feature) backs its Map with a BTreeMap, so
    // object keys iterate ALPHABETICALLY: api_key sorts before db_password.
    let text =
        r#"{"outputs":{"db_password":{"value":"tok-ABC-123"},"api_key":{"value":"key-XYZ-789"}}}"#;
    let pairs = testing::parse_tfstate_tuples(text);
    assert_eq!(
        pairs,
        vec![
            (
                "tfstate-output.api_key".to_string(),
                "key-XYZ-789".to_string(),
                1,
            ),
            (
                "tfstate-output.db_password".to_string(),
                "tok-ABC-123".to_string(),
                1,
            ),
        ],
        "two outputs must surface both pairs in BTreeMap-sorted key order"
    );
}

#[test]
fn tfstate_resource_instance_attribute_extracts_exact_context() {
    // Single instance, no index_key -> context is "<type>.<name>.<attr_path>".
    let text = r#"{"resources":[{"type":"aws_secret","name":"db","instances":[{"attributes":{"password":"res-secret-111"}}]}]}"#;
    let pairs = testing::parse_tfstate_tuples(text);
    assert_eq!(
        pairs,
        vec![(
            "aws_secret.db.password".to_string(),
            "res-secret-111".to_string(),
            1,
        )],
        "a resource instance attribute must render as <type>.<name>.<attribute>"
    );
}

#[test]
fn tfstate_deep_but_within_limit_still_surfaces_buried_secret() {
    // 40 nested `"values"` wrappers around the outputs block. This is well under
    // both serde_json's parse recursion limit (128) and the 256 traversal cap,
    // so the recursive `extract_tfstate_outputs` walk MUST reach and surface the
    // buried secret while terminating cleanly.
    let depth = 40;
    let mut text = String::new();
    for _ in 0..depth {
        text.push_str(r#"{"values":"#);
    }
    text.push_str(r#"{"outputs":{"secret_out":{"value":"deep-nested-secret-42"}}}"#);
    for _ in 0..depth {
        text.push('}');
    }

    let pairs = testing::parse_tfstate_tuples(&text);
    assert_eq!(
        pairs,
        vec![(
            "tfstate-output.secret_out".to_string(),
            "deep-nested-secret-42".to_string(),
            1,
        )],
        "a secret nested 40 `values` levels deep must still surface exactly once"
    );
}

#[test]
fn tfstate_nested_beyond_recursion_cap_surfaces_no_deeper_pair() {
    // 400 nested wrappers exceeds serde_json's parse recursion limit (and would
    // exceed the 256 traversal cap even if it parsed), so the buried secret must
    // NOT surface. The parse fails closed -> exactly zero pairs, and no stack
    // overflow / panic.
    let depth = 400;
    let mut text = String::new();
    for _ in 0..depth {
        text.push_str(r#"{"values":"#);
    }
    text.push_str(r#"{"outputs":{"secret_out":{"value":"way-too-deep-secret"}}}"#);
    for _ in 0..depth {
        text.push('}');
    }

    let pairs = testing::parse_tfstate_tuples(&text);
    assert_eq!(
        pairs.len(),
        0,
        "a doc nested beyond the recursion/parse cap must surface zero pairs"
    );
    assert!(
        !pairs.iter().any(|(_, v, _)| v == "way-too-deep-secret"),
        "the over-deep secret must never be surfaced"
    );
}

#[test]
fn tfstate_array_nesting_bomb_terminates_without_panic() {
    // 100_000 open brackets: serde_json's recursion guard rejects this long
    // before any stack exhaustion. The contract is: return empty, do not panic.
    let depth = 100_000;
    let mut text = String::with_capacity(depth * 2 + 32);
    for _ in 0..depth {
        text.push('[');
    }
    text.push_str(r#""deep-array-secret""#);
    for _ in 0..depth {
        text.push(']');
    }

    let pairs = testing::parse_tfstate_tuples(&text);
    assert_eq!(
        pairs.len(),
        0,
        "a 100k-deep array bomb must parse-fail closed to zero pairs, not overflow"
    );
}

#[test]
fn tfstate_malformed_json_yields_empty() {
    // Unterminated string / missing braces -> serde_json parse error -> the
    // parser fails closed with an empty extraction (Law 10: no partial silent
    // surface).
    let text = r#"{"outputs": {"x": {"value": "unterminated"#;
    let pairs = testing::parse_tfstate_tuples(text);
    assert_eq!(
        pairs.len(),
        0,
        "malformed tfstate JSON must yield exactly zero extracted pairs"
    );
}

#[test]
fn tfstate_non_object_root_yields_empty() {
    // A bare JSON scalar root is valid JSON but has no outputs/resources to walk.
    let pairs = testing::parse_tfstate_tuples(r#""just-a-string""#);
    assert_eq!(
        pairs.len(),
        0,
        "a scalar-root tfstate has no extractable pairs"
    );
}

// ---------------------------------------------------------------------------
// YAML (k8s Secret) — the recursive YAML parser + base64 decode-through.
// ---------------------------------------------------------------------------

#[test]
fn k8s_secret_flat_data_block_base64_decodes_exact_pair() {
    // cGFzc3dvcmQxMjM= == base64("password123"). data: values are base64-decoded
    // and anchored on the "<key>: <encoded>" line.
    let text = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db-creds\ndata:\n  password: cGFzc3dvcmQxMjM=\n";
    let pairs = testing::parse_k8s_secret_tuples(text);
    assert_eq!(
        pairs,
        vec![("password".to_string(), "password123".to_string(), 6)],
        "a k8s Secret data: value must base64-decode to its plaintext, anchored to line 6"
    );
}

#[test]
fn k8s_secret_string_data_surfaces_raw_value() {
    // stringData: values are already plaintext and surface raw (no base64).
    let text = "kind: Secret\nstringData:\n  db_pass: raw-secret-value\n";
    let pairs = testing::parse_k8s_secret_tuples(text);
    assert_eq!(
        pairs,
        vec![("db_pass".to_string(), "raw-secret-value".to_string(), 3)],
        "a k8s Secret stringData: value must surface raw at line 3"
    );
}

#[test]
fn k8s_secret_non_secret_kind_yields_empty() {
    // kind must be Secret for the k8s extractor to walk the maps; a ConfigMap is
    // not a Secret so nothing is extracted.
    let text = "kind: ConfigMap\ndata:\n  password: cGFzc3dvcmQxMjM=\n";
    let pairs = testing::parse_k8s_secret_tuples(text);
    assert_eq!(pairs.len(), 0, "a non-Secret kind must extract zero pairs");
}

#[test]
fn k8s_secret_deeply_nested_yaml_terminates_empty() {
    // serde_yaml enforces its own parse recursion limit (128) before building a
    // Value; a 300-deep flow sequence exceeds it and fails closed to empty with
    // no panic.
    let depth = 300;
    let mut text = String::from("kind: Secret\ndata:\n  blob: ");
    for _ in 0..depth {
        text.push('[');
    }
    for _ in 0..depth {
        text.push(']');
    }
    text.push('\n');

    let pairs = testing::parse_k8s_secret_tuples(&text);
    assert_eq!(
        pairs.len(),
        0,
        "a 300-deep YAML flow sequence must parse-fail closed to zero pairs"
    );
}

#[test]
fn k8s_secret_malformed_yaml_yields_empty() {
    // A tab in indentation is illegal YAML -> parse error -> empty.
    let text = "kind: Secret\ndata:\n\tpassword: cGFzc3dvcmQxMjM=\n";
    let pairs = testing::parse_k8s_secret_tuples(text);
    assert_eq!(
        pairs.len(),
        0,
        "tab-indented (illegal) YAML must fail closed to zero pairs"
    );
}

// ---------------------------------------------------------------------------
// YAML (docker-compose) — recursive environment-block discovery.
// ---------------------------------------------------------------------------

#[test]
fn compose_environment_mapping_extracts_exact_pair() {
    let text = "services:\n  web:\n    environment:\n      API_KEY: secret-value-123\n";
    let pairs = testing::parse_docker_compose_tuples(text);
    assert_eq!(
        pairs,
        vec![("API_KEY".to_string(), "secret-value-123".to_string(), 4)],
        "a compose environment mapping entry must surface (key, value, line 4)"
    );
}

#[test]
fn compose_environment_sequence_splits_key_equals_value() {
    // Sequence form `- KEY=VALUE` splits on the first '='.
    let text = "services:\n  api:\n    environment:\n      - DB_TOKEN=tok-987-xyz\n";
    let pairs = testing::parse_docker_compose_tuples(text);
    assert_eq!(
        pairs,
        vec![("DB_TOKEN".to_string(), "tok-987-xyz".to_string(), 4)],
        "a compose `- KEY=VALUE` entry must split into (KEY, VALUE, line 4)"
    );
}

#[test]
fn compose_deeply_nested_yaml_terminates_empty() {
    // A 300-deep flow mapping exceeds serde_yaml's parse recursion limit; the
    // find_environment_pairs walk never runs because parsing fails closed.
    let depth = 300;
    let mut text = String::new();
    for _ in 0..depth {
        text.push_str("a: {");
    }
    text.push_str("environment: {LEAK: buried-compose-secret}");
    for _ in 0..depth {
        text.push('}');
    }
    text.push('\n');

    let pairs = testing::parse_docker_compose_tuples(&text);
    assert_eq!(
        pairs.len(),
        0,
        "a 300-deep compose mapping must parse-fail closed, surfacing no buried env secret"
    );
}

// ---------------------------------------------------------------------------
// HCL — line-based parser with explicit lookahead / heredoc bounds.
// ---------------------------------------------------------------------------

#[test]
fn hcl_variable_default_extracts_exact_pair() {
    let text = "variable \"db_password\" {\n  default = \"hunter2-secret-value\"\n}\n";
    let pairs = testing::parse_hcl_tuples(text);
    assert_eq!(
        pairs,
        vec![(
            "db_password".to_string(),
            "hunter2-secret-value".to_string(),
            2,
        )],
        "a variable block default must attribute to the variable name at line 2"
    );
}

#[test]
fn hcl_flat_assignment_extracts_exact_pair() {
    let text = "api_key = \"flat-hcl-secret-42\"\n";
    let pairs = testing::parse_hcl_tuples(text);
    assert_eq!(
        pairs,
        vec![("api_key".to_string(), "flat-hcl-secret-42".to_string(), 1)],
        "a flat tfvars assignment must surface (name, value, line 1)"
    );
}

#[test]
fn hcl_closed_heredoc_joins_body_lines() {
    let text = "config = <<EOF\nsecret-heredoc-line-1\nsecret-heredoc-line-2\nEOF\n";
    let pairs = testing::parse_hcl_tuples(text);
    assert_eq!(
        pairs,
        vec![(
            "config".to_string(),
            "secret-heredoc-line-1\nsecret-heredoc-line-2".to_string(),
            2,
        )],
        "a closed heredoc must join its body with '\\n' and anchor to the first content line"
    );
}

#[test]
fn hcl_unterminated_heredoc_is_bounded_and_surfaces_nothing() {
    // No closing EOF within MAX_HEREDOC_LINES (512): collect_heredoc returns None
    // -> no pair. With 20_000 content lines this proves the scan is BOUNDED and
    // does not run to the end of an adversarially long unterminated heredoc.
    let mut text = String::from("config = <<EOF\n");
    for i in 0..20_000 {
        text.push_str(&format!("filler content line number {i}\n"));
    }
    let pairs = testing::parse_hcl_tuples(&text);
    assert_eq!(
        pairs.len(),
        0,
        "an unterminated 20k-line heredoc must surface zero pairs (bounded lookahead)"
    );
}

// ---------------------------------------------------------------------------
// Oversize-skip coverage-gap partition (the size-cap decode-through classifier).
// ---------------------------------------------------------------------------

#[test]
fn oversize_skip_counted_for_decode_through_k8s_secret() {
    // A recognised decode-through format (k8s Secret .yaml) that is NOT a
    // decode-derived buffer counts as a real coverage gap when skipped oversize.
    let text = "kind: Secret\ndata:\n  x: eA==\n";
    assert!(
        testing::structured_oversize_skip_is_counted(text, Some("secret.yaml"), false),
        "an oversize k8s Secret skip must count as a decode-through coverage gap"
    );
}

#[test]
fn oversize_skip_not_counted_for_context_only_env() {
    // .env is context-only (values are still byte-scanned), so an oversize skip
    // loses no decode surface and must NOT count.
    let text = "API_KEY=some-value\n";
    assert!(
        !testing::structured_oversize_skip_is_counted(text, Some(".env"), false),
        "an oversize .env skip is lossless context-only and must NOT count"
    );
}

#[test]
fn oversize_skip_not_counted_for_decode_derived_buffer() {
    // A decode-derived buffer already had its encoded surface decoded upstream,
    // so even a decode-through format skip must not be re-counted.
    let text = "kind: Secret\ndata:\n  x: eA==\n";
    assert!(
        !testing::structured_oversize_skip_is_counted(text, Some("secret.yaml"), true),
        "a decode-derived buffer skip must never be counted (no false-loud telemetry)"
    );
}
