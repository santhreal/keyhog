mod support;

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::testing::{
    candidate_source_roles_for_test, classify_code_source_candidate_for_test,
    code_source_semantic_window_bytes_for_test, named_detector_fixture_defaults,
    structured_max_traversal_depth_for_test,
};

fn classify(text: &str, path: &str, needle: &str, expected_role: &str) {
    let start = text.find(needle).expect("fixture contains candidate");
    let evidence = classify_code_source_candidate_for_test(text, path, start, start + needle.len())
        .unwrap_or_else(|| panic!("{needle:?} in {path} classifies"));
    assert_eq!(evidence.role, expected_role, "{needle:?} in {path}");
    assert_eq!(evidence.confidence, "parsed");
    assert_eq!(evidence.candidate_span, (start, start + needle.len()));
    assert!(evidence.value_span.0 <= start && start + needle.len() <= evidence.value_span.1);
    assert!(evidence.key_path_spans.is_empty());
}

/// WHY: each supported language must classify exact candidate spans across its
/// literal, identifier, regex, test-scope, command-argument, and option forms.
#[test]
fn supported_code_languages_emit_exact_roles() {
    let rust = r##"
const RAW: &str = r#"CFGCODE_RUST_RAW_123456"#;
struct CFGCODE_RUST_IDENTIFIER_123456;
let grammar = Regex::new(r"CFGCODE_RUST_REGEX_[A-Z0-9]+").unwrap();
let command = Command::new("tool").arg("CFGCODE_RUST_COMMAND_123456");
let option = Arg::new("--password=CFGCODE_RUST_OPTION_123456");
let macro_text = format!("CFGCODE_RUST_MACRO_123456");
let macro_grammar = regex!(r"CFGCODE_RUST_MACRO_REGEX_[A-Z]+");
"##;
    classify(
        rust,
        "src/main.rs",
        "CFGCODE_RUST_RAW_123456",
        "string-literal",
    );
    classify(
        rust,
        "src/main.rs",
        "CFGCODE_RUST_IDENTIFIER_123456",
        "identifier-type-member-name",
    );
    classify(
        rust,
        "src/main.rs",
        "CFGCODE_RUST_REGEX_",
        "regex-rule-definition",
    );
    classify(
        rust,
        "src/main.rs",
        "CFGCODE_RUST_MACRO_123456",
        "string-literal",
    );
    classify(
        rust,
        "src/main.rs",
        "CFGCODE_RUST_MACRO_REGEX_",
        "regex-rule-definition",
    );
    classify(
        rust,
        "src/main.rs",
        "CFGCODE_RUST_COMMAND_123456",
        "command-argument-value",
    );
    classify(
        rust,
        "src/main.rs",
        "CFGCODE_RUST_OPTION_123456",
        "command-option-declaration",
    );

    let javascript = r#"
const template = `prefix-CFGCODE_JS_TEMPLATE_123456-${suffix}-CFGCODE_JS_SUFFIX_123456`;
const grammar = /CFGCODE_JS_REGEX_[A-Z0-9]+/gi;
spawn("tool", ["CFGCODE_JS_COMMAND_123456"]);
program.option("--password CFGCODE_JS_OPTION_123456");
test("retains fixture", () => { const token = "CFGCODE_JS_TEST_123456"; });
"#;
    classify(
        javascript,
        "src/main.ts",
        "CFGCODE_JS_TEMPLATE_123456",
        "string-literal",
    );
    classify(
        javascript,
        "src/main.ts",
        "CFGCODE_JS_SUFFIX_123456",
        "string-literal",
    );
    classify(
        javascript,
        "src/main.ts",
        "CFGCODE_JS_REGEX_",
        "regex-rule-definition",
    );
    classify(
        javascript,
        "src/main.ts",
        "CFGCODE_JS_COMMAND_123456",
        "command-argument-value",
    );
    classify(
        javascript,
        "src/main.ts",
        "CFGCODE_JS_OPTION_123456",
        "command-option-declaration",
    );
    classify(
        javascript,
        "src/main.ts",
        "CFGCODE_JS_TEST_123456",
        "test-fixture",
    );

    let python = r#"
"""CFGCODE_PY_DOCSTRING_123456"""
grammar = re.compile(r"CFGCODE_PY_REGEX_[A-Z0-9]+")
subprocess.run(["tool", "CFGCODE_PY_COMMAND_123456"])
parser.add_argument("--password=CFGCODE_PY_OPTION_123456")
class TestClient:
    def test_token(self):
        token = "CFGCODE_PY_TEST_123456"
"#;
    classify(
        python,
        "src/main.py",
        "CFGCODE_PY_DOCSTRING_123456",
        "string-literal",
    );
    classify(
        python,
        "src/main.py",
        "CFGCODE_PY_REGEX_",
        "regex-rule-definition",
    );
    classify(
        python,
        "src/main.py",
        "CFGCODE_PY_COMMAND_123456",
        "command-argument-value",
    );
    classify(
        python,
        "src/main.py",
        "CFGCODE_PY_OPTION_123456",
        "command-option-declaration",
    );
    classify(
        python,
        "src/main.py",
        "CFGCODE_PY_TEST_123456",
        "test-fixture",
    );
}

/// WHY: inline test scopes must cover long bodies and nested modules without a
/// fixed line-count heuristic. Path-owned test files use the existing Tier-B
/// test-path rules and apply to all supported languages.
#[test]
fn test_scope_roles_cover_long_and_path_owned_fixtures() {
    let filler = "    let keep_scanning = true;\n".repeat(140);
    let rust = format!(
        "#[test]\nfn long_test() {{\n{filler}    let token = \"CFGCODE_LONG_TEST_123456\";\n}}\n"
    );
    classify(
        &rust,
        "src/lib.rs",
        "CFGCODE_LONG_TEST_123456",
        "test-fixture",
    );

    let module = r##"
#[cfg(test)]
mod tests {
    fn helper() { let token = r#"CFGCODE_TEST_MODULE_123456"#; }
}
"##;
    classify(
        module,
        "src/lib.rs",
        "CFGCODE_TEST_MODULE_123456",
        "test-fixture",
    );

    classify(
        "const token = 'CFGCODE_PATH_TEST_123456';",
        "tests/client.spec.ts",
        "CFGCODE_PATH_TEST_123456",
        "test-fixture",
    );
}
/// WHY: negative-evidence roles must not leak across a closed call or test
/// scope. A nearby command/test marker cannot relabel an unrelated candidate.
#[test]
fn roles_do_not_escape_owning_syntax() {
    let rust = r#"
Command::new("tool").arg("safe");
let token = "CFGCODE_AFTER_COMMAND_123456";
#[test]
fn fixture() { let token = "CFGCODE_INSIDE_TEST_123456"; }
let live = "CFGCODE_AFTER_TEST_123456";
"#;
    classify(
        rust,
        "src/main.rs",
        "CFGCODE_AFTER_COMMAND_123456",
        "string-literal",
    );
    classify(
        rust,
        "src/main.rs",
        "CFGCODE_INSIDE_TEST_123456",
        "test-fixture",
    );
    classify(
        rust,
        "src/main.rs",
        "CFGCODE_AFTER_TEST_123456",
        "string-literal",
    );

    let javascript = r#"
program.option("--safe");
const token = "--CFGCODE_AFTER_OPTION_123456";
test("fixture", () => { const token = "CFGCODE_INSIDE_JS_TEST_123456"; });
const live = "CFGCODE_AFTER_JS_TEST_123456";
"#;
    classify(
        javascript,
        "src/main.ts",
        "CFGCODE_AFTER_OPTION_123456",
        "string-literal",
    );
    classify(
        javascript,
        "src/main.ts",
        "CFGCODE_INSIDE_JS_TEST_123456",
        "test-fixture",
    );
    classify(
        javascript,
        "src/main.ts",
        "CFGCODE_AFTER_JS_TEST_123456",
        "string-literal",
    );
}

/// WHY: malformed, truncated, unsupported, or over-budget code has no semantic
/// proof. A candidate before the malformed suffix must also abstain.
#[test]
fn parser_failures_and_unsupported_code_abstain() {
    for (text, path) in [
        ("let token = \"CFGCODE_BAD_RUST", "src/main.rs"),
        (
            "const token = 'CFGCODE_EARLY_JS';\nconst broken = `",
            "src/main.ts",
        ),
        ("token = 'CFGCODE_EARLY_PY'\nbroken = \"", "src/main.py"),
        ("let token = \"CFGCODE_BAD_BRACE\"; }", "src/main.rs"),
    ] {
        let start = text.find("CFGCODE").expect("fixture candidate");
        assert!(
            classify_code_source_candidate_for_test(text, path, start, start + "CFGCODE".len(),)
                .is_none(),
            "malformed {path} must abstain"
        );
    }

    let unsupported = "token = 'CFGCODE_UNKNOWN_123456'";
    let start = unsupported.find("CFGCODE").unwrap();
    assert!(classify_code_source_candidate_for_test(
        unsupported,
        "src/main.go",
        start,
        start + "CFGCODE_UNKNOWN_123456".len(),
    )
    .is_none());

    let oversized = format!(
        "const padding = \"{}\"; const token = \"CFGCODE_BIG_123456\";",
        "a".repeat(code_source_semantic_window_bytes_for_test())
    );
    let start = oversized.find("CFGCODE_BIG_123456").unwrap();
    assert!(classify_code_source_candidate_for_test(
        &oversized,
        "src/main.ts",
        start,
        start + "CFGCODE_BIG_123456".len(),
    )
    .is_none());

    let over_depth = structured_max_traversal_depth_for_test() + 1;
    let over_nested = format!(
        "{}\"CFGCODE_DEEP_123456\"{}",
        "{".repeat(over_depth),
        "}".repeat(over_depth)
    );
    let start = over_nested.find("CFGCODE_DEEP_123456").unwrap();
    assert!(classify_code_source_candidate_for_test(
        &over_nested,
        "src/main.ts",
        start,
        start + "CFGCODE_DEEP_123456".len(),
    )
    .is_none());
}

fn semantic_detector() -> DetectorSpec {
    DetectorSpec {
        id: "code-role-fixture".into(),
        name: "Code role fixture".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: r"[A-Z0-9]{4}CFGCODE[A-Z0-9_]{16}".into(),
            ..Default::default()
        }],
        keywords: vec!["CFGCODE".into()],
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

/// WHY: lexical roles are evidence, never a retrieval filter. Parsed test and
/// string candidates retain typed sidecars, while malformed code retains the
/// finding with explicit abstention.
#[test]
fn production_candidates_retain_code_roles_without_changing_recall() {
    let valid = candidate_chunk(
        "const token = \"AB12CFGCODEQ7W8E9R0T1Y2U3I4\";",
        "src/main.ts",
    );
    let roles = candidate_source_roles_for_test(vec![semantic_detector()], &valid)
        .expect("valid source-code scan");
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].detector_id, "code-role-fixture");
    assert_eq!(roles[0].role, "string-literal");
    assert_eq!(roles[0].confidence, "parsed");

    let malformed = candidate_chunk(
        "const token = \"AB12CFGCODEQ7W8E9R0T1Y2U3I4\"; const broken = `",
        "src/main.ts",
    );
    let roles = candidate_source_roles_for_test(vec![semantic_detector()], &malformed)
        .expect("abstaining source-code scan");
    assert_eq!(roles.len(), 1, "parser abstention must preserve recall");
    assert_eq!(roles[0].role, "unknown");
    assert_eq!(roles[0].confidence, "abstained");
}
