use keyhog_scanner::context::*;

#[test]
fn assignment_context() {
    let lines = vec!["API_KEY = sk-proj-abc123"];
    assert_eq!(infer_context(&lines, 0, None), CodeContext::Assignment);
}

#[test]
fn comment_context() {
    let lines = vec!["# old key: sk-proj-abc123"];
    assert_eq!(infer_context(&lines, 0, None), CodeContext::Comment);
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
    assert!(is_false_positive_context(&lines, 0, Some("deps/go.sum")));
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
    let lines = vec![r#"ETag: W/"xoxb-8f3a9b2c1d4e5f60718293a4b5c6d7e8f9a0b""#];
    assert!(is_false_positive_context(&lines, 0, None));
}
