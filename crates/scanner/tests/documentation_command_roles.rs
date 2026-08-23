mod support;

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{
    testing::{
        candidate_source_roles_with_config_for_test, classify_candidate_source_semantics_for_test,
        document_source_semantic_window_bytes_for_test, named_detector_fixture_defaults,
        structured_markdown_fences_for_test,
    },
    ScannerConfig,
};

fn classify(text: &str, path: &str, needle: &str, expected_role: &str) {
    let start = text.find(needle).expect("fixture contains candidate");
    let evidence =
        classify_candidate_source_semantics_for_test(text, path, start, start + needle.len())
            .unwrap_or_else(|| panic!("{needle:?} in {path} classifies"));
    assert_eq!(evidence.role, expected_role, "{needle:?} in {path}");
    assert_eq!(evidence.confidence, "parsed");
    assert_eq!(evidence.candidate_span, (start, start + needle.len()));
    assert!(evidence.value_span.0 <= start && start + needle.len() <= evidence.value_span.1);
}

/// WHY: Markdown prose and inline code are documentation evidence, while shell
/// and structured fences must preserve the source role of a real value.
#[test]
fn markdown_prose_inline_code_and_shell_fences_have_exact_roles() {
    let markdown = r#"
Use CFGDOC_PROSE_123456 as the public identifier.

The field is `token=CFGDOC_INLINE_123456`.

```sh
tool --password CFGDOC_COMMAND_123456
```

```env
API_TOKEN=CFGDOC_ENV_FENCE_123456
```

```json
{"api_token":"CFGDOC_JSON_FENCE_123456"}
```
"#;
    classify(
        markdown,
        "docs/guide.md",
        "CFGDOC_PROSE_123456",
        "prose-documentation",
    );
    classify(
        markdown,
        "docs/guide.md",
        "CFGDOC_INLINE_123456",
        "prose-documentation",
    );
    classify(
        markdown,
        "docs/guide.md",
        "CFGDOC_COMMAND_123456",
        "command-argument-value",
    );
    classify(
        markdown,
        "docs/guide.md",
        "CFGDOC_ENV_FENCE_123456",
        "environment-assignment-value",
    );
    classify(
        markdown,
        "docs/guide.md",
        "CFGDOC_JSON_FENCE_123456",
        "structured-assignment-value",
    );
}

/// WHY: adding a supported structured fence must turn the suite red until its
/// exact parser role is covered. This enumerates the production registry rather
/// than a second hardcoded language list.
#[test]
fn every_structured_markdown_fence_uses_its_value_parser() {
    const NEEDLE: &str = "CFGDOC_STRUCTURED_FENCE_123456";

    for (language, _) in structured_markdown_fences_for_test() {
        let (body, role) = match *language {
            "env" | "dotenv" => (
                format!("API_TOKEN={NEEDLE}"),
                "environment-assignment-value",
            ),
            "json" => (
                format!(r#"{{"api_token":"{NEEDLE}"}}"#),
                "structured-assignment-value",
            ),
            "jsonl" | "ndjson" => (
                format!(r#"{{"api_token":"{NEEDLE}"}}"#),
                "structured-assignment-value",
            ),
            "toml" => (
                format!(r#"api_token = "{NEEDLE}""#),
                "structured-assignment-value",
            ),
            "yaml" | "yml" => (
                format!(r#"api_token: "{NEEDLE}""#),
                "structured-assignment-value",
            ),
            "ini" | "cfg" | "conf" => (
                format!(r#"api_token = {NEEDLE}"#),
                "structured-assignment-value",
            ),
            "properties" => (format!("api_token={NEEDLE}"), "structured-assignment-value"),
            added => panic!("add a structured Markdown fence fixture for {added}"),
        };
        let markdown = format!("```{language}\n{body}\n```\n");
        classify(&markdown, "docs/guide.md", NEEDLE, role);
    }
}

/// WHY: roff escapes and option declarations are distinct syntax. Escaped
/// formatting remains prose; a declared option is negative declaration evidence.
#[test]
fn roff_prose_and_option_declarations_do_not_conflate() {
    let roff = r#"
.SH DESCRIPTION
The token grammar is CFGDOC_ROFF_PROSE_123456 and uses \fBbold\fR text.
.TP
.B --password=CFGDOC_ROFF_OPTION_123456
"#;
    classify(
        roff,
        "docs/keyhog.1",
        "CFGDOC_ROFF_PROSE_123456",
        "prose-documentation",
    );
    classify(
        roff,
        "docs/keyhog.1",
        "CFGDOC_ROFF_OPTION_123456",
        "command-option-declaration",
    );
}

/// WHY: shell tokenization must retain explicit option values, inline option
/// values, quoted arguments, and assignments without treating comments as proof.
#[test]
fn shell_command_values_and_assignments_have_exact_roles() {
    let shell = r#"
PASSWORD=CFGDOC_ENV_123456
tool --password CFGDOC_OPTION_VALUE_123456
other --token="CFGDOC_INLINE_VALUE_123456"
printf '%s' 'CFGDOC_QUOTED_ARG_123456'
# CFGDOC_COMMENT_123456
"#;
    classify(
        shell,
        "scripts/deploy.sh",
        "CFGDOC_ENV_123456",
        "environment-assignment-value",
    );
    classify(
        shell,
        "scripts/deploy.sh",
        "CFGDOC_OPTION_VALUE_123456",
        "command-argument-value",
    );
    classify(
        shell,
        "scripts/deploy.sh",
        "CFGDOC_INLINE_VALUE_123456",
        "command-argument-value",
    );
    classify(
        shell,
        "scripts/deploy.sh",
        "CFGDOC_QUOTED_ARG_123456",
        "command-argument-value",
    );
    let start = shell.find("CFGDOC_COMMENT_123456").unwrap();
    assert!(classify_candidate_source_semantics_for_test(
        shell,
        "scripts/deploy.sh",
        start,
        start + "CFGDOC_COMMENT_123456".len(),
    )
    .is_none());

    classify(
        "RUN tool --password CFGDOC_DOCKER_VALUE_123456",
        "Dockerfile",
        "CFGDOC_DOCKER_VALUE_123456",
        "command-argument-value",
    );
}

/// WHY: detector and rule TOML fields own executable regex and fixture roles.
/// Arbitrary configuration fields retain ordinary structured assignment roles.
#[test]
fn structured_rule_fields_are_data_owned_and_path_bounded() {
    let detector = r#"
[[detector.patterns]]
regex = "CFGDOC_REGEX_[A-Z0-9]{16}"
description = "CFGDOC_DESCRIPTION_123456"
[[detector.tests]]
test_negative = "CFGDOC_FIXTURE_123456"
"#;
    classify(
        detector,
        "detectors/example.toml",
        "CFGDOC_REGEX_",
        "regex-rule-definition",
    );
    classify(
        detector,
        "detectors/example.toml",
        "CFGDOC_DESCRIPTION_123456",
        "prose-documentation",
    );
    classify(
        detector,
        "detectors/example.toml",
        "CFGDOC_FIXTURE_123456",
        "test-fixture",
    );

    let ordinary = r#"
regex = "CFGDOC_CONFIG_VALUE_123456"
positive = "CFGDOC_CONFIG_POSITIVE_123456"
"#;
    classify(
        ordinary,
        "settings.toml",
        "CFGDOC_CONFIG_VALUE_123456",
        "structured-assignment-value",
    );
    classify(
        ordinary,
        "settings.toml",
        "CFGDOC_CONFIG_POSITIVE_123456",
        "structured-assignment-value",
    );
}

/// WHY: malformed, truncated, unsupported, or over-budget documents and shell
/// input carry no semantic proof and must abstain.
#[test]
fn parser_failures_and_unsupported_documents_abstain() {
    for (text, path) in [
        ("text CFGDOC_BAD_FENCE_123456\n```sh\ntool", "guide.md"),
        (
            "```json\n{\"token\":\"CFGDOC_BAD_JSON_123456\"\n```\n",
            "guide.md",
        ),
        ("tool --password 'CFGDOC_BAD_SHELL_123456", "deploy.sh"),
        (".B \"--password=CFGDOC_BAD_ROFF_123456", "keyhog.1"),
    ] {
        let start = text.find("CFGDOC").unwrap();
        assert!(classify_candidate_source_semantics_for_test(
            text,
            path,
            start,
            start + "CFGDOC".len(),
        )
        .is_none());
    }

    let unsupported = "CFGDOC_UNKNOWN_123456";
    assert!(classify_candidate_source_semantics_for_test(
        unsupported,
        "guide.adoc",
        0,
        unsupported.len(),
    )
    .is_none());

    let oversized = format!(
        "{} CFGDOC_BIG_123456",
        "a".repeat(document_source_semantic_window_bytes_for_test())
    );
    let start = oversized.find("CFGDOC_BIG_123456").unwrap();
    assert!(classify_candidate_source_semantics_for_test(
        &oversized,
        "guide.md",
        start,
        start + "CFGDOC_BIG_123456".len(),
    )
    .is_none());
}

fn semantic_detector() -> DetectorSpec {
    DetectorSpec {
        id: "documentation-role-fixture".into(),
        name: "Documentation role fixture".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: r"[A-Z0-9]{4}CFGDOCR[A-Z0-9_]{16}".into(),
            ..Default::default()
        }],
        keywords: vec!["CFGDOCR".into()],
        min_confidence: Some(0.0),
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

/// WHY: documentation and command roles are evidence, not retrieval filters.
/// A valid documented command retains its role; malformed input retains recall
/// through explicit abstention.
#[test]
fn production_candidates_retain_document_roles_without_changing_recall() {
    let mut config = ScannerConfig::default();
    config.penalize_test_paths = false;
    let valid = candidate_chunk(
        "```sh\ntool --password AB12CFGDOCRQ7W8E9R0T1Y2U3I4\n```\n",
        "guide.md",
    );
    let roles = candidate_source_roles_with_config_for_test(
        vec![semantic_detector()],
        &valid,
        config.clone(),
    )
    .expect("valid documentation scan");
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].detector_id, "documentation-role-fixture");
    assert_eq!(roles[0].role, "command-argument-value");
    assert_eq!(roles[0].confidence, "parsed");

    let malformed = candidate_chunk("AB12CFGDOCRQ7W8E9R0T1Y2U3I4\n```sh\nunclosed", "guide.md");
    let roles =
        candidate_source_roles_with_config_for_test(vec![semantic_detector()], &malformed, config)
            .expect("abstaining documentation scan");
    assert_eq!(roles.len(), 1, "parser abstention must preserve recall");
    assert_eq!(roles[0].role, "unknown");
    assert_eq!(roles[0].confidence, "abstained");
}
