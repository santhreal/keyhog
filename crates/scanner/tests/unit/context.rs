use keyhog_scanner::context::{infer_context, CodeContext};
use keyhog_scanner::testing::context::is_false_positive_context;

#[test]
fn assignment_context() {
    let lines = vec!["API_KEY = sk-proj-abc123"];
    assert_eq!(infer_context(&lines, 0, None), CodeContext::Assignment);
}

#[test]
fn comment_context() {
    // A prose comment with NO assignment/mapping shape is Comment. (A commented
    // `key: value` / `KEY=value` is deliberately classified Assignment instead -
    // see `commented_assignment_context` - so a secret hidden in a commented
    // config line is not downgraded. The earlier fixture `# old key: sk-proj-...`
    // carried a `key: value` mapping and therefore correctly resolved to
    // Assignment under that policy; use genuine prose here.)
    let lines = vec!["# old key was sk-proj-abc123, now rotated"];
    assert_eq!(infer_context(&lines, 0, None), CodeContext::Comment);
}

#[test]
fn commented_assignment_context() {
    for line in [
        "# API_KEY=sk-proj-abc123",
        "// token = sk-proj-abc123",
        "/* SECRET: sk-proj-abc123 */",
        "<!-- OPENAI_API_KEY=sk-proj-abc123 -->",
    ] {
        assert_eq!(
            infer_context(&[line], 0, None),
            CodeContext::Assignment,
            "{line:?} should be treated as a commented-out config assignment"
        );
    }
}

#[test]
fn test_file_context() {
    let lines = vec!["key = sk-proj-abc123"];
    assert_eq!(
        infer_context(&lines, 0, Some("tests/test_auth.py")),
        CodeContext::TestCode
    );
}

#[test]
fn encrypted_block_context() {
    let lines = vec!["$ANSIBLE_VAULT;1.1;AES256", "6162636465666768"];
    assert_eq!(infer_context(&lines, 1, None), CodeContext::Encrypted);
}

#[test]
fn documentation_context() {
    let lines = vec![
        "```bash",
        "curl -H 'Authorization: Bearer sk-proj-abc'",
        "```",
    ];
    assert_eq!(infer_context(&lines, 1, None), CodeContext::Documentation);
}

#[test]
fn test_function_context() {
    let lines = vec![
        "def test_api_call():",
        "    key = 'sk-proj-abc123'",
        "    assert call(key)",
    ];
    assert_eq!(infer_context(&lines, 1, None), CodeContext::TestCode);
}

#[test]
fn confidence_multipliers() {
    assert!(
        CodeContext::Assignment.confidence_multiplier()
            > CodeContext::Comment.confidence_multiplier()
    );
    assert!(
        CodeContext::Comment.confidence_multiplier()
            > CodeContext::Encrypted.confidence_multiplier()
    );
    assert!(
        CodeContext::TestCode.confidence_multiplier()
            < CodeContext::Assignment.confidence_multiplier()
    );
}

#[test]
fn false_positive_context_detects_go_sum() {
    let lines = vec!["github.com/example/module v1.0.0 h1:AKIAIOSFODNN7EXAMPLEabc"];
    assert!(is_false_positive_context(&lines, 0, Some("deps/go.sum")));
}

#[test]
fn false_positive_context_does_not_suppress_bare_h1_outside_go_sum() {
    let lines = vec!["api_secret = \"h1:AKIAIOSFODNN7EXAMPLEabc\""];
    assert!(
        !is_false_positive_context(&lines, 0, Some("src/config.env")),
        "a bare h1: substring outside go.sum must not suppress a real secret"
    );
}

#[test]
fn false_positive_context_detects_strict_go_sum_checksum_without_path() {
    let lines = vec!["github.com/example/module v1.0.0 h1:Fr1vK8xdpbQ5OCaCB3ABAfRtq5B4JZc0jRUXPv7Q3k0="];
    assert!(
        is_false_positive_context(&lines, 0, None),
        "pathless go.sum-shaped h1 checksums should still suppress when the checksum token shape is strict"
    );
}

#[test]
fn false_positive_context_detects_configmap_binary_data_block() {
    let lines = vec![
        "kind: ConfigMap",
        "binaryData:",
        "  cert-fingerprint-sha256: Z2hwX2FiYw==",
    ];
    assert!(is_false_positive_context(&lines, 2, None));
}

#[test]
fn false_positive_context_detects_git_lfs_pointer() {
    let lines = vec![
        "version https://git-lfs.github.com/spec/v1",
        "oid sha256:sk-proj-abcdefghijklmnopqrstuvwxyz123456",
    ];
    assert!(is_false_positive_context(&lines, 1, None));
}

#[test]
fn false_positive_context_detects_integrity_hash() {
    let lines = vec!["integrity sha512-sk-proj-abcdefghijklmnopqrstuvwxyz123456"];
    assert!(is_false_positive_context(&lines, 0, None));
}

#[test]
fn false_positive_context_detects_sum_file_path() {
    let lines = vec!["github.com/example/module v1.0.0 checksum"];
    assert!(
        !is_false_positive_context(&lines, 0, Some("deps/go.sum")),
        "go.sum path alone is not enough; the line must carry an h1 checksum token"
    );
}

#[test]
fn false_positive_context_detects_renovate_digest() {
    let lines = vec![r#""branchName": "renovate/node-8f3a9b2c1d4e5f60""#];
    assert!(is_false_positive_context(&lines, 0, None));
}

#[test]
fn false_positive_context_detects_cors_header() {
    let lines = vec!["Access-Control-Allow-Headers: Authorization, X-API-Key"];
    assert!(is_false_positive_context(&lines, 0, None));
}

#[test]
fn false_positive_context_detects_http_cache_header() {
    let lines = vec![r#"ETag: W/concat!("xox", "b-8f3a9b2c1d4e5f60718293a4b5c6d7e8f9a0b")"#];
    assert!(is_false_positive_context(&lines, 0, None));
}
