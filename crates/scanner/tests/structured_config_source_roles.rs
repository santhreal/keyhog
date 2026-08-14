mod support;

use keyhog_core::{
    AnchorSemanticRole, CaptureSemanticRole, Chunk, ChunkMetadata, DetectorSpec, PatternSpec,
    SemanticSourceRole, Severity,
};
use keyhog_scanner::testing::{
    candidate_source_roles_and_cache_for_test, candidate_source_roles_for_test,
    classify_structured_source_candidate_for_test, named_detector_fixture_defaults,
    structured_max_traversal_depth_for_test, structured_source_semantic_window_bytes_for_test,
};
use support::contracts::{make_chunk, scanner};

fn classify<'a>(
    text: &'a str,
    path: &str,
    needle: &str,
) -> (
    keyhog_scanner::testing::StructuredSourceEvidenceForTest,
    Vec<&'a str>,
) {
    let start = text.find(needle).expect("fixture contains candidate");
    let end = start + needle.len();
    let evidence = classify_structured_source_candidate_for_test(text, path, start, end)
        .unwrap_or_else(|| panic!("structured candidate {needle:?} in {path} classifies"));
    let keys = evidence
        .key_path_spans
        .iter()
        .map(|(start, end)| &text[*start..*end])
        .collect();
    let expected_role = if path.rsplit('/').next().unwrap_or(path).starts_with(".env") {
        "environment-assignment-value"
    } else {
        "structured-assignment-value"
    };
    assert_eq!(evidence.role, expected_role);
    assert_eq!(evidence.confidence, "parsed");
    assert_eq!(evidence.candidate_span, (start, end));
    assert!(evidence.value_span.0 <= start && end <= evidence.value_span.1);
    (evidence, keys)
}

/// WHY: each supported structured syntax must preserve source byte spans and a
/// key path without parsing unrelated repository bytes. The matrix includes
/// nested, escaped, multiline, anchor, alias, template, comment, empty-setting,
/// wide-mapping, and section forms.
#[test]
fn supported_structured_formats_emit_exact_candidate_roles_and_key_paths() {
    let json = r#"{"auth":{"token":"prefix_\"_CFGPROV_ABC123_suffix"}}"#;
    let (_, keys) = classify(json, "config.json", "CFGPROV_ABC123");
    assert_eq!(keys, ["auth", "token"]);

    let jsonl = "{\"ignored\":true}\n{\"token\":\"CFGPROV_JSONL_123456\"}\n";
    let (_, keys) = classify(jsonl, "events.jsonl", "CFGPROV_JSONL_123456");
    assert_eq!(keys, ["token"]);

    let toml = "[auth]\ncredentials.token = \"\"\"first\nCFGPROV_TOML_123456\nlast\"\"\"\n";
    let (_, keys) = classify(toml, "settings.toml", "CFGPROV_TOML_123456");
    assert_eq!(keys, ["auth", "credentials", "token"]);

    let toml_inner_assignment =
        "[auth]\nblob = \"\"\"\ntoken = \"CFGPROV_TOML_INNER_123456\"\n\"\"\"\n";
    let (_, keys) = classify(
        toml_inner_assignment,
        "settings.toml",
        "CFGPROV_TOML_INNER_123456",
    );
    assert_eq!(keys, ["auth", "blob"]);

    let yaml = "auth:\n  token: &primary \"CFGPROV_YAML_123456\"\n  alias: *primary_alias\n  template: ${CFGPROV_TEMPLATE_123456}\n  block: |-\n    CFGPROV_BLOCK_123456\n";
    let (_, keys) = classify(yaml, "settings.yaml", "CFGPROV_YAML_123456");
    assert_eq!(keys, ["auth", "token"]);
    let (_, keys) = classify(yaml, "settings.yaml", "primary_alias");
    assert_eq!(keys, ["auth", "alias"]);
    let (_, keys) = classify(yaml, "settings.yaml", "CFGPROV_TEMPLATE_123456");
    assert_eq!(keys, ["auth", "template"]);
    let (_, keys) = classify(yaml, "settings.yaml", "CFGPROV_BLOCK_123456");
    assert_eq!(keys, ["auth", "block"]);

    let yaml_inner_mapping = "auth:\n  block: |\n    token: CFGPROV_YAML_INNER_123456\n";
    let (_, keys) = classify(
        yaml_inner_mapping,
        "settings.yaml",
        "CFGPROV_YAML_INNER_123456",
    );
    assert_eq!(keys, ["auth", "block"]);

    let dotenv = "export APP_TOKEN=\"first\nCFGPROV_ENV_123456\n${ROTATED_TOKEN}\"\n";
    let (evidence, keys) = classify(dotenv, ".env.production", "CFGPROV_ENV_123456");
    assert_eq!(evidence.role, "environment-assignment-value");
    assert_eq!(keys, ["APP_TOKEN"]);

    let dotenv_comment = "TOKEN=don't-CFGPROV_ENV_COMMENT_123456 # rotated\n";
    let (evidence, keys) = classify(dotenv_comment, ".env", "CFGPROV_ENV_COMMENT_123456");
    assert_eq!(keys, ["TOKEN"]);
    assert_eq!(
        &dotenv_comment[evidence.value_span.0..evidence.value_span.1],
        "don't-CFGPROV_ENV_COMMENT_123456"
    );

    let ini = "[auth]\ntoken = CFGPROV_INI_123456 ; rotated quarterly\n";
    let (_, keys) = classify(ini, "settings.ini", "CFGPROV_INI_123456");
    assert_eq!(keys, ["auth", "token"]);

    let ini_comment = "[auth]\ntoken = it's-CFGPROV_INI_COMMENT_123456 ; rotated\n";
    let (evidence, keys) = classify(ini_comment, "settings.ini", "CFGPROV_INI_COMMENT_123456");
    assert_eq!(keys, ["auth", "token"]);
    assert_eq!(
        &ini_comment[evidence.value_span.0..evidence.value_span.1],
        "it's-CFGPROV_INI_COMMENT_123456"
    );

    let commented_toml =
        "# token = \"retired\"\n[[services.auth]] # active\ntoken = \"CFGPROV_TOML_COMMENT_123456\"\n";
    let (_, keys) = classify(
        commented_toml,
        "settings.toml",
        "CFGPROV_TOML_COMMENT_123456",
    );
    assert_eq!(keys, ["services", "auth", "token"]);

    let commented_yaml = "# token: \"retired\"\nauth:\n  token: CFGPROV_YAML_COMMENT_123456\n";
    let (_, keys) = classify(
        commented_yaml,
        "settings.yaml",
        "CFGPROV_YAML_COMMENT_123456",
    );
    assert_eq!(keys, ["auth", "token"]);

    let commented_dotenv = "# TOKEN=\"retired\"\nTOKEN=CFGPROV_ENV_COMMENTED_123456\n";
    let (_, keys) = classify(commented_dotenv, ".env", "CFGPROV_ENV_COMMENTED_123456");
    assert_eq!(keys, ["TOKEN"]);

    let sparse_ini =
        "[auth] ; active credentials\nempty = ; rotated\ntoken = CFGPROV_INI_EMPTY_123456\n";
    let (_, keys) = classify(sparse_ini, "settings.ini", "CFGPROV_INI_EMPTY_123456");
    assert_eq!(keys, ["auth", "token"]);

    let wide_yaml = format!(
        "auth:\n{}  token: CFGPROV_YAML_WIDE_123456\n",
        (0..512)
            .map(|index| format!("  public_{index}: value\n"))
            .collect::<String>()
    );
    let (_, keys) = classify(&wide_yaml, "settings.yaml", "CFGPROV_YAML_WIDE_123456");
    assert_eq!(keys, ["auth", "token"]);
}

/// WHY: invalid, truncated, unsupported, or over-budget syntax carries no
/// semantic proof. Abstention must never become a suppression decision.
#[test]
fn parser_failures_and_unsupported_windows_abstain() {
    let malformed = [
        ("{\"token\":\"CFGPROV_BAD_JSON\"", "config.json"),
        ("token = \"CFGPROV_BAD_TOML", "config.toml"),
        (
            "blob = \"\"\"\ntoken = \"CFGPROV_BAD_TOML_INNER\"",
            "config.toml",
        ),
        ("token: \"CFGPROV_BAD_YAML", "config.yaml"),
        ("TOKEN=\"CFGPROV_BAD_ENV", ".env"),
        ("token = \"CFGPROV_BAD_INI", "config.ini"),
        (
            "{\"token\":\"CFGPROV_EARLY_JSON\",\"broken\":",
            "config.json",
        ),
        (
            "{\"token\":\"CFGPROV_EARLY_JSONL\"}\n{\"broken\":",
            "events.jsonl",
        ),
        ("token = \"CFGPROV_EARLY_TOML\"\nbroken = \"", "config.toml"),
        ("token: CFGPROV_EARLY_YAML\nbroken: \"", "config.yaml"),
        ("TOKEN=CFGPROV_EARLY_ENV\nBROKEN=\"", ".env"),
        ("token=CFGPROV_EARLY_INI\nbroken=\"", "config.ini"),
    ];
    for (text, path) in malformed {
        let start = text.find("CFGPROV").expect("fixture candidate");
        assert!(
            classify_structured_source_candidate_for_test(
                text,
                path,
                start,
                start + "CFGPROV".len(),
            )
            .is_none(),
            "malformed {path} must abstain"
        );
    }

    let unsupported = "token = CFGPROV_UNKNOWN_123456";
    let start = unsupported.find("CFGPROV").unwrap();
    assert!(classify_structured_source_candidate_for_test(
        unsupported,
        "config.unknown",
        start,
        start + "CFGPROV_UNKNOWN_123456".len(),
    )
    .is_none());

    let cap = structured_source_semantic_window_bytes_for_test();
    let oversized = format!(
        "{{\"padding\":\"{}\",\"token\":\"CFGPROV_BIG_123456\"}}",
        "a".repeat(cap)
    );
    let start = oversized.find("CFGPROV_BIG_123456").unwrap();
    assert!(classify_structured_source_candidate_for_test(
        &oversized,
        "config.json",
        start,
        start + "CFGPROV_BIG_123456".len(),
    )
    .is_none());

    for (assignment, path) in [
        ("token = ", "config.toml"),
        ("token: ", "config.yaml"),
        ("TOKEN=", ".env"),
        ("token = ", "config.ini"),
    ] {
        let oversized = format!(
            "padding={}\n{assignment}CFGPROV_BIG_LINE_123456",
            "a".repeat(cap)
        );
        let start = oversized.find("CFGPROV_BIG_LINE_123456").unwrap();
        assert!(
            classify_structured_source_candidate_for_test(
                &oversized,
                path,
                start,
                start + "CFGPROV_BIG_LINE_123456".len(),
            )
            .is_none(),
            "over-budget {path} must abstain"
        );
    }

    let over_depth = structured_max_traversal_depth_for_test() + 1;
    let over_nested = format!(
        "{}{{\"key\":\"CFGPROV_DEEP_123456\"}}{}",
        "[".repeat(over_depth),
        "]".repeat(over_depth)
    );
    let start = over_nested.find("CFGPROV_DEEP_123456").unwrap();
    assert!(classify_structured_source_candidate_for_test(
        &over_nested,
        "config.json",
        start,
        start + "CFGPROV_DEEP_123456".len(),
    )
    .is_none());
}

/// WHY: a structured role is positive syntax evidence, not proof that every
/// scalar is a credential. Rule strings and public identifiers remain silent
/// while retaining exact structured value classification.
#[test]
fn config_rule_strings_and_public_identifiers_do_not_invent_findings() {
    let cases = [
        (
            "rule = \"DRUID_PASSWORD[=:]+([A-Za-z0-9]{16,})\"",
            "rules.toml",
            "DRUID_PASSWORD",
            "druid-credentials",
        ),
        (
            "atlas: GlyphAtlas",
            "renderer.yaml",
            "GlyphAtlas",
            "mongodb-atlas-api-key",
        ),
    ];
    let scanner = scanner();
    for (text, path, candidate, detector_id) in cases {
        let (_, keys) = classify(text, path, candidate);
        assert_eq!(keys.len(), 1);
        let findings = scanner
            .scan(&make_chunk(text, "filesystem", path))
            .expect("config decoy scan");
        assert!(
            findings
                .iter()
                .all(|finding| finding.detector_id.as_ref() != detector_id),
            "{detector_id} surfaced for structured non-secret {path}"
        );
    }
}

fn semantic_detector() -> DetectorSpec {
    DetectorSpec {
        id: "structured-role-fixture".into(),
        name: "Structured role fixture".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: r"[A-Z0-9]{4}CFGPROV[A-Z0-9_]{16}".into(),
            ..Default::default()
        }],
        keywords: vec!["CFGPROV".into()],
        min_confidence: Some(0.0),
        capture_role: CaptureSemanticRole::AssignmentValue,
        anchor_role: AnchorSemanticRole::ExactKey,
        allowed_source_roles: vec![SemanticSourceRole::StructuredAssignmentValue],
        ..named_detector_fixture_defaults()
    }
}

fn candidate_chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.to_owned().into(),
        metadata: ChunkMetadata {
            path: Some(path.into()),
            source_type: "filesystem".into(),
            ..Default::default()
        },
    }
}

/// WHY: source roles are evidence, not a new retrieval filter. Valid structured
/// assignments retain typed proof through the production emission sidecar;
/// malformed and unsupported inputs retain the finding with explicit abstention.
#[test]
fn production_candidates_retain_roles_without_changing_recall() {
    let valid = candidate_chunk(
        concat!(
            "{\"primary\":\"AB12CFGPROVQ7W8E9R0T1Y2U3I4\",",
            "\"secondary\":\"CD34CFGPROVA1S2D3F4G5H6J7K8\"}"
        ),
        "config.json",
    );
    let roles = candidate_source_roles_for_test(vec![semantic_detector()], &valid)
        .expect("valid structured scan");
    assert_eq!(roles.len(), 2, "one cached source index serves both values");
    assert!(
        roles
            .iter()
            .all(|role| role.detector_id == "structured-role-fixture"
                && role.role == "structured-assignment-value"
                && role.confidence == "parsed"),
        "every candidate retains parsed structured-role provenance: {roles:?}"
    );

    for chunk in [
        candidate_chunk(
            "{\"arbitrary\":\"AB12CFGPROVQ7W8E9R0T1Y2U3I4\"",
            "malformed.json",
        ),
        candidate_chunk("arbitrary=AB12CFGPROVQ7W8E9R0T1Y2U3I4", "config.unknown"),
    ] {
        let roles = candidate_source_roles_for_test(vec![semantic_detector()], &chunk)
            .expect("abstaining structured scan");
        assert_eq!(roles.len(), 1, "parser abstention must preserve recall");
        assert_eq!(roles[0].role, "unknown");
        assert_eq!(roles[0].confidence, "abstained");
    }
}

/// WHY: structured parsing is evidence enrichment, not an admission gate. A
/// candidate rejected synchronously by test-path policy must not build an index.
#[test]
fn synchronously_suppressed_candidates_do_not_parse_structured_sources() {
    let chunk = candidate_chunk(
        "{\"primary\":\"AB12CFGPROVQ7W8E9R0T1Y2U3I4\"}",
        "tests/config.json",
    );
    let (roles, cache_built) =
        candidate_source_roles_and_cache_for_test(vec![semantic_detector()], &chunk)
            .expect("test-path candidate scan");
    assert!(
        roles.is_empty(),
        "suppressed candidate must not emit: {roles:?}"
    );
    assert!(
        !cache_built,
        "synchronous suppression must run before structured parsing"
    );
}
