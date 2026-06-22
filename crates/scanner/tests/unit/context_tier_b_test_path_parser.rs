use keyhog_scanner::context::{infer_context, CodeContext};
use keyhog_scanner::testing::context::parse_test_path_rules_for_test;

fn valid_rules() -> &'static str {
    r#"
schema_version = 1

[test_paths]
filename_prefixes = ["test_"]
filename_suffixes = ["_test.rs", ".spec.ts"]
path_components = ["tests", "__tests__"]
"#
}

#[test]
fn test_path_rules_tier_b_parser_rejects_invalid_vocabularies() {
    let empty_suffixes = parse_test_path_rules_for_test(
        r#"
schema_version = 1

[test_paths]
filename_prefixes = ["test_"]
filename_suffixes = []
path_components = ["tests"]
"#,
    )
    .expect_err("empty suffix list must fail closed");
    assert!(
        empty_suffixes.contains("filename_suffixes")
            && empty_suffixes.contains("at least one entry"),
        "unexpected empty suffix error: {empty_suffixes}"
    );

    let unsupported_schema = parse_test_path_rules_for_test(
        &valid_rules().replace("schema_version = 1", "schema_version = 2"),
    )
    .expect_err("unsupported schema must fail closed");
    assert!(
        unsupported_schema.contains("schema_version"),
        "unexpected schema error: {unsupported_schema}"
    );

    let duplicate = parse_test_path_rules_for_test(
        r#"
schema_version = 1

[test_paths]
filename_prefixes = ["test_", "test_"]
filename_suffixes = ["_test.rs"]
path_components = ["tests"]
"#,
    )
    .expect_err("duplicate rule must fail closed");
    assert!(
        duplicate.contains("duplicate"),
        "unexpected duplicate error: {duplicate}"
    );

    let separator = parse_test_path_rules_for_test(
        r#"
schema_version = 1

[test_paths]
filename_prefixes = ["test_"]
filename_suffixes = ["foo/bar"]
path_components = ["tests"]
"#,
    )
    .expect_err("path separators in filename fragments must fail closed");
    assert!(
        separator.contains("path separators"),
        "unexpected separator error: {separator}"
    );

    let dotted_component = parse_test_path_rules_for_test(
        r#"
schema_version = 1

[test_paths]
filename_prefixes = ["test_"]
filename_suffixes = ["_test.rs"]
path_components = ["foo.spec"]
"#,
    )
    .expect_err("filename-shaped path components must fail closed");
    assert!(
        dotted_component.contains("path segment"),
        "unexpected dotted component error: {dotted_component}"
    );
}

#[test]
fn bundled_test_path_rules_drive_context_classification() {
    let lines = ["token = 'fixture_secret'"];
    for path in [
        "pkg/auth_test.go",
        "src/__tests__/fixture.ts",
        "spec/features/auth_spec.rb",
        "client/session.spec.ts",
        "tests/fixtures/creds.env",
    ] {
        assert_eq!(
            infer_context(&lines, 0, Some(path)),
            CodeContext::TestCode,
            "bundled Tier-B test path rules must classify {path} as TestCode"
        );
    }

    assert_ne!(
        infer_context(&lines, 0, Some("src/prod_auth.go")),
        CodeContext::TestCode,
        "ordinary production paths must not be classified as TestCode"
    );
}
