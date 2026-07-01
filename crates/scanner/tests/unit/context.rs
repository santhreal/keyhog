use keyhog_scanner::context::{infer_context, CodeContext};
use keyhog_scanner::testing::context::{
    is_false_positive_context, is_false_positive_match_context,
};

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
    let lines =
        vec!["github.com/example/module v1.0.0 h1:Fr1vK8xdpbQ5OCaCB3ABAfRtq5B4JZc0jRUXPv7Q3k0="];
    assert!(
        is_false_positive_context(&lines, 0, None),
        "pathless go.sum-shaped h1 checksums should still suppress when the checksum token shape is strict"
    );
}

#[test]
fn false_positive_match_context_does_not_suppress_adjacent_go_sum_checksum() {
    let text = concat!(
        "github.com/example/module v1.0.0 h1:Fr1vK8xdpbQ5OCaCB3ABAfRtq5B4JZc0jRUXPv7Q3k0=\n",
        "api_key = sk-proj-abcdefghijklmnopqrstuvwxyz123456\n",
    );
    let offset = text.find("sk-proj").expect("fixture contains secret");
    assert!(
        !is_false_positive_match_context(text, offset, None),
        "a Go module checksum on a neighboring line must not suppress the credential line"
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
fn false_positive_match_context_does_not_suppress_configmap_without_line_scope() {
    let text = "kind: ConfigMap\nbinaryData:\n  cert-fingerprint-sha256: Z2hwX2FiYw==\n";
    let offset = text.find("Z2hw").expect("fixture contains base64 value");
    assert!(
        !is_false_positive_match_context(text, offset, None),
        "ConfigMap binaryData suppression requires line-indexed YAML block ownership"
    );
}

#[test]
fn false_positive_context_detects_later_configmap_binary_data_value() {
    let text = concat!(
        "kind: ConfigMap\n",
        "binaryData:\n",
        "  first.bin: QUJDREVGRw==\n",
        "  second.bin: SElKS0xNTg==\n",
        "  third.bin: T1BRUlNUVQ==\n",
    );
    let lines: Vec<_> = text.lines().collect();
    assert!(is_false_positive_context(&lines, 4, None));
}

#[test]
fn false_positive_context_does_not_suppress_secret_like_configmap_binary_data_value() {
    let lines = vec![
        "kind: ConfigMap",
        "binaryData:",
        "  api-token: sk-proj-abcdefghijklmnopqrstuvwxyz123456",
    ];
    assert!(
        !is_false_positive_context(&lines, 2, None),
        "binaryData suppression is for base64 scalar data, not secret-shaped cleartext values"
    );
}

#[test]
fn false_positive_context_does_not_suppress_data_block_after_configmap_binary_data() {
    let lines = vec![
        "kind: ConfigMap",
        "binaryData:",
        "  cert.bin: QUJDREVGRw==",
        "data:",
        "  api-token: Z2hwX2FiYw==",
    ];
    assert!(
        !is_false_positive_context(&lines, 4, None),
        "binaryData suppression must stop when indentation returns to a sibling data block"
    );
}

#[test]
fn false_positive_match_context_does_not_suppress_data_block_after_configmap_binary_data() {
    let text = concat!(
        "kind: ConfigMap\n",
        "binaryData:\n",
        "  cert.bin: QUJDREVGRw==\n",
        "data:\n",
        "  api-token: Z2hwX2FiYw==\n",
    );
    let offset = text.rfind("Z2hw").expect("fixture contains data value");
    assert!(
        !is_false_positive_match_context(text, offset, None),
        "match-window binaryData suppression must honor YAML sibling block boundaries"
    );
}

#[test]
fn false_positive_match_context_does_not_suppress_secret_like_configmap_binary_data_value() {
    let text =
        "kind: ConfigMap\nbinaryData:\n  api-token: sk-proj-abcdefghijklmnopqrstuvwxyz123456\n";
    let offset = text.find("sk-proj").expect("fixture contains secret");
    assert!(
        !is_false_positive_match_context(text, offset, None),
        "match-window binaryData suppression must not hide cleartext secret-shaped values"
    );
}

// ── ConfigMap binaryData block-header lookback (the >8-entry FP regression) ───
//
// `is_inside_configmap_binary_data_block` walks back to the `binaryData:` header
// by indentation. A fixed 8-line lookback truncated that walk, so every 9th and
// later base64 blob in a block failed to find its header and leaked as a false
// positive. The header search now clears any realistic block. Entry `e` (0-based)
// of `configmap_binary_block(n)` lives at line index `2 + e`; the header is at
// line index 1.

/// A ConfigMap `binaryData:` block with `entries` base64 value lines.
fn configmap_binary_block(entries: usize) -> Vec<String> {
    const B64: [&str; 4] = [
        "QUJDREVGRw==",
        "SElKS0xNTg==",
        "T1BRUlNUVQ==",
        "Z2hwX2FiYw==",
    ];
    let mut lines = vec!["kind: ConfigMap".to_string(), "binaryData:".to_string()];
    for i in 0..entries {
        lines.push(format!("  entry-{i}.bin: {}", B64[i % B64.len()]));
    }
    lines
}

fn borrow(lines: &[String]) -> Vec<&str> {
    lines.iter().map(String::as_str).collect()
}

#[test]
fn configmap_binary_data_ninth_entry_beyond_old_cap_suppressed() {
    // The regression: the 9th entry (line index 10) sits past the old 8-line cap.
    let owned = configmap_binary_block(9);
    let lines = borrow(&owned);
    assert!(
        is_false_positive_context(&lines, 10, None),
        "9th binaryData entry must still resolve its header and be suppressed"
    );
}

#[test]
fn configmap_binary_data_eighth_entry_within_old_cap_still_suppressed() {
    // Boundary control: the 8th entry (index 9) was reachable under the old cap.
    let owned = configmap_binary_block(8);
    let lines = borrow(&owned);
    assert!(is_false_positive_context(&lines, 9, None));
}

#[test]
fn configmap_binary_data_first_entry_still_suppressed() {
    let owned = configmap_binary_block(9);
    let lines = borrow(&owned);
    assert!(is_false_positive_context(&lines, 2, None));
}

#[test]
fn configmap_binary_data_fiftieth_entry_suppressed() {
    let owned = configmap_binary_block(50);
    let lines = borrow(&owned);
    assert!(is_false_positive_context(&lines, 51, None));
}

#[test]
fn configmap_binary_data_hundredth_entry_suppressed() {
    let owned = configmap_binary_block(100);
    let lines = borrow(&owned);
    assert!(is_false_positive_context(&lines, 101, None));
}

#[test]
fn configmap_binary_data_two_hundredth_entry_suppressed() {
    let owned = configmap_binary_block(200);
    let lines = borrow(&owned);
    assert!(is_false_positive_context(&lines, 201, None));
}

#[test]
fn configmap_binary_data_thousandth_entry_suppressed() {
    // Well within the generous lookback bound; proves the cap is not merely a
    // slightly-larger magic number.
    let owned = configmap_binary_block(1000);
    let lines = borrow(&owned);
    assert!(is_false_positive_context(&lines, 1001, None));
}

#[test]
fn configmap_binary_data_all_hundred_entries_suppressed() {
    let owned = configmap_binary_block(100);
    let lines = borrow(&owned);
    for entry in 0..100 {
        assert!(
            is_false_positive_context(&lines, 2 + entry, None),
            "entry {entry} (line {}) must be suppressed",
            2 + entry
        );
    }
}

#[test]
fn configmap_binary_data_deep_secret_like_value_not_suppressed() {
    // A cleartext secret-shaped value deep in a large block must NOT be hidden.
    let mut owned = configmap_binary_block(15);
    owned.push("  api-token: sk-proj-abcdefghijklmnopqrstuvwxyz123456".to_string());
    let lines = borrow(&owned);
    assert!(
        !is_false_positive_context(&lines, 17, None),
        "a secret-shaped value must not be suppressed even deep in a binaryData block"
    );
}

#[test]
fn configmap_data_block_after_deep_binary_data_not_suppressed() {
    // A sibling `data:` block after a large binaryData block: its values are
    // secrets, not binary — the nearest dedent parent is `data:`, not the header.
    let mut owned = configmap_binary_block(15);
    owned.push("data:".to_string());
    owned.push("  api-token: Z2hwX2FiYw==".to_string());
    let lines = borrow(&owned);
    assert!(
        !is_false_positive_context(&lines, 18, None),
        "a data: block value after a deep binaryData block must not be suppressed"
    );
}

#[test]
fn configmap_binary_data_lookback_stops_at_first_dedent_even_if_header_below() {
    // The walk must return at the FIRST less-indented parent. A `binaryData:`
    // header that sits ABOVE an intervening non-header parent must not be reached.
    let lines = vec!["binaryData:", "otherblock:", "  entry.bin: QUJDREVGRw=="];
    assert!(
        !is_false_positive_context(&lines, 2, None),
        "the nearest dedent parent (otherblock:) wins; a binaryData header above it is not the owner"
    );
}

#[test]
fn configmap_binary_data_blank_lines_between_entries_still_suppressed() {
    let lines = vec![
        "kind: ConfigMap",
        "binaryData:",
        "  a.bin: QUJDREVGRw==",
        "",
        "  b.bin: SElKS0xNTg==",
        "",
        "  c.bin: T1BRUlNUVQ==",
    ];
    assert!(
        is_false_positive_context(&lines, 6, None),
        "blank lines between entries must be skipped, not stop the header search"
    );
}

#[test]
fn configmap_binary_data_header_case_insensitive() {
    let lines = vec!["kind: ConfigMap", "BinaryData:", "  a.bin: QUJDREVGRw=="];
    assert!(is_false_positive_context(&lines, 2, None));
}

#[test]
fn configmap_binary_data_header_trailing_whitespace_recognized() {
    let lines = vec!["kind: ConfigMap", "binaryData:   ", "  a.bin: QUJDREVGRw=="];
    assert!(is_false_positive_context(&lines, 2, None));
}

#[test]
fn configmap_binary_data_zero_indent_value_not_suppressed() {
    // A value at column 0 has no parent to own it.
    let lines = vec!["binaryData:", "x.bin: QUJDREVGRw=="];
    assert!(!is_false_positive_context(&lines, 1, None));
}

#[test]
fn configmap_binary_data_deeper_nested_values_suppressed() {
    // binaryData: at indent 2, values at indent 4.
    let lines = vec!["spec:", "  binaryData:", "    a.bin: QUJDREVGRw=="];
    assert!(is_false_positive_context(&lines, 2, None));
}

#[test]
fn configmap_binary_data_non_header_word_not_matched() {
    // `binaryDataFoo:` is a different key, not the block header.
    let lines = vec!["kind: ConfigMap", "binaryDataFoo:", "  a.bin: QUJDREVGRw=="];
    assert!(!is_false_positive_context(&lines, 2, None));
}

#[test]
fn configmap_binary_data_no_header_above_not_suppressed() {
    let lines = vec!["kind: ConfigMap", "data:", "  a.bin: QUJDREVGRw=="];
    assert!(!is_false_positive_context(&lines, 2, None));
}

#[test]
fn configmap_binary_data_quoted_value_suppressed() {
    let lines = vec![
        "kind: ConfigMap",
        "binaryData:",
        "  a.bin: \"QUJDREVGRw==\"",
    ];
    assert!(is_false_positive_context(&lines, 2, None));
}

#[test]
fn configmap_binary_data_dedent_to_metadata_parent_not_suppressed() {
    // The value's nearest dedent parent is `metadata:`, so the binaryData header
    // two blocks up does not own it.
    let lines = vec![
        "binaryData:",
        "  cert.bin: QUJDREVGRw==",
        "metadata:",
        "  name.bin: SElKS0xNTg==",
    ];
    assert!(!is_false_positive_context(&lines, 3, None));
}

#[test]
fn false_positive_context_detects_git_lfs_pointer() {
    let lines = vec![
        "version https://git-lfs.github.com/spec/v1",
        "oid sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "size 12345",
    ];
    assert!(is_false_positive_context(&lines, 1, None));
}

#[test]
fn false_positive_match_context_detects_git_lfs_pointer() {
    let text = concat!(
        "version https://git-lfs.github.com/spec/v1\n",
        "oid sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        "size 12345\n"
    );
    let offset = text.find("012345").expect("fixture contains oid");
    assert!(is_false_positive_match_context(text, offset, None));
}

#[test]
fn false_positive_match_context_does_not_suppress_adjacent_git_lfs_pointer() {
    let text = concat!(
        "version https://git-lfs.github.com/spec/v1\n",
        "oid sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        "size 12345\n",
        "api_key = sk-proj-abcdefghijklmnopqrstuvwxyz123456\n",
    );
    let offset = text.find("sk-proj").expect("fixture contains secret");
    assert!(
        !is_false_positive_match_context(text, offset, None),
        "a Git LFS pointer in the surrounding window must not suppress a different credential line"
    );
}

#[test]
fn false_positive_context_does_not_suppress_nearby_git_lfs_prose() {
    let lines = vec![
        "# git-lfs stores large binaries out of band",
        "OPENAI_API_KEY = sk-proj-abcdefghijklmnopqrstuvwxyz123456",
    ];
    assert!(
        !is_false_positive_context(&lines, 1, None),
        "a nearby git-lfs mention is not a Git LFS pointer and must not hide a real credential"
    );
}

#[test]
fn false_positive_context_does_not_suppress_out_of_order_git_lfs_pointer() {
    let lines = vec![
        "size 12345",
        "version https://git-lfs.github.com/spec/v1",
        "oid sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ];
    assert!(
        !is_false_positive_context(&lines, 2, None),
        "Git LFS suppression requires the size line after the object id"
    );
}

#[test]
fn false_positive_context_does_not_suppress_malformed_git_lfs_oid() {
    let lines = vec![
        "version https://git-lfs.github.com/spec/v1",
        "oid sha256:sk-proj-abcdefghijklmnopqrstuvwxyz123456",
        "size 12345",
    ];
    assert!(
        !is_false_positive_context(&lines, 1, None),
        "Git LFS suppression requires a 64-hex object id, not any oid sha256 line"
    );
}

#[test]
fn false_positive_context_detects_integrity_hash() {
    let lines = vec!["integrity sha512-Z2hwX2FiYw=="];
    assert!(is_false_positive_context(&lines, 0, None));
}

#[test]
fn false_positive_match_context_detects_integrity_hash() {
    let text = r#"<script integrity="sha256-Z2hwX2FiYw=="></script>"#;
    let offset = text.find("Z2hw").expect("fixture contains sri hash");
    assert!(is_false_positive_match_context(text, offset, None));
}

#[test]
fn false_positive_context_does_not_suppress_adjacent_integrity_prose() {
    let lines = vec![
        "# integrity check uses sha256-digest metadata",
        "api_key = sk-proj-abcdefghijklmnopqrstuvwxyz123456",
    ];
    assert!(
        !is_false_positive_context(&lines, 1, None),
        "integrity prose on an adjacent line is not an SRI hash for the secret line"
    );
}

#[test]
fn false_positive_match_context_does_not_suppress_adjacent_integrity_prose() {
    let text = "# integrity check uses sha256-digest metadata\napi_key = sk-proj-abcdefghijklmnopqrstuvwxyz123456\n";
    let offset = text.find("sk-proj").expect("fixture contains secret");
    assert!(
        !is_false_positive_match_context(text, offset, None),
        "match-window integrity checks must not let adjacent prose hide the current secret line"
    );
}

#[test]
fn false_positive_context_does_not_suppress_integrity_key_secret_value() {
    let lines = vec!["integrity: sk-proj-abcdefghijklmnopqrstuvwxyz123456"];
    assert!(
        !is_false_positive_context(&lines, 0, None),
        "an integrity-named config key holding a secret-shaped value must surface"
    );
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
fn false_positive_context_does_not_suppress_renovate_digest_without_match_offset() {
    let lines = vec![r#""branchName": "renovate/node-8f3a9b2c1d4e5f60""#];
    assert!(
        !is_false_positive_context(&lines, 0, None),
        "Renovate suppression requires the match offset so same-line credentials are not hidden"
    );
}

#[test]
fn false_positive_match_context_detects_renovate_digest() {
    let text = r#""branchName": "renovate/node-8f3a9b2c1d4e5f60""#;
    let offset = text.find("8f3a").expect("fixture contains digest");
    assert!(is_false_positive_match_context(text, offset, None));
}

#[test]
fn false_positive_match_context_detects_second_renovate_digest_on_line() {
    let text = r#""branches": ["renovate/no-digest", "renovate/node-8f3a9b2c1d4e5f60"]"#;
    let offset = text.find("8f3a").expect("fixture contains second digest");
    assert!(
        is_false_positive_match_context(text, offset, None),
        "Renovate suppression must inspect every renovate/ token on the line"
    );
}

#[test]
fn false_positive_match_context_does_not_suppress_renovate_branch_prefix() {
    let text = r#""branchName": "renovate/node-8f3a9b2c1d4e5f60""#;
    let offset = text.find("node").expect("fixture contains branch prefix");
    assert!(
        !is_false_positive_match_context(text, offset, None),
        "Renovate suppression must overlap the digest run, not any byte inside the branch name"
    );
}

#[test]
fn false_positive_context_does_not_suppress_adjacent_renovate_branch() {
    let lines = vec![
        r#""branchName": "renovate/node-8f3a9b2c1d4e5f60","#,
        r#""renovate_token": "ghp_abcdefghijklmnopqrstuvwxyz123456""#,
    ];
    assert!(
        !is_false_positive_context(&lines, 1, None),
        "a Renovate branch on an adjacent line is not context for suppressing a real token"
    );
}

#[test]
fn false_positive_match_context_does_not_suppress_adjacent_renovate_branch() {
    let text = concat!(
        r#""branchName": "renovate/node-8f3a9b2c1d4e5f60","#,
        "\n",
        r#""renovate_token": "ghp_abcdefghijklmnopqrstuvwxyz123456""#,
        "\n",
    );
    let offset = text.find("ghp_").expect("fixture contains token");
    assert!(
        !is_false_positive_match_context(text, offset, None),
        "match-window Renovate suppression must not leak to adjacent token lines"
    );
}

#[test]
fn false_positive_context_does_not_suppress_renovate_token_value() {
    let lines = vec![r#""renovate_token": "renovate/ghp_abcdefghijklmnopqrstuvwxyz123456""#];
    assert!(
        !is_false_positive_context(&lines, 0, None),
        "a secret value containing renovate/ is not a Renovate branch digest"
    );
}

#[test]
fn false_positive_match_context_does_not_suppress_renovate_token_value() {
    let text = r#""renovate_token": "renovate/ghp_abcdefghijklmnopqrstuvwxyz123456""#;
    let offset = text.find("ghp_").expect("fixture contains token");
    assert!(
        !is_false_positive_match_context(text, offset, None),
        "offset-aware Renovate suppression must not hide secret values containing renovate/"
    );
}

#[test]
fn false_positive_match_context_does_not_suppress_same_line_renovate_branch_neighbor() {
    let text = concat!(
        r#""branchName": "renovate/node-8f3a9b2c1d4e5f60", "#,
        r#""renovate_token": "ghp_abcdefghijklmnopqrstuvwxyz123456""#,
    );
    let offset = text.find("ghp_").expect("fixture contains token");
    assert!(
        !is_false_positive_match_context(text, offset, None),
        "Renovate suppression must apply to the matched branch token, not any other token on the same line"
    );
}

#[test]
fn false_positive_context_detects_cors_header() {
    let lines = vec!["Access-Control-Allow-Headers: Authorization, X-API-Key"];
    assert!(is_false_positive_context(&lines, 0, None));
}

#[test]
fn false_positive_context_does_not_suppress_custom_access_control_secret() {
    let lines = vec!["access-control-api-token: sk-proj-abcdefghijklmnopqrstuvwxyz123456"];
    assert!(
        !is_false_positive_context(&lines, 0, None),
        "only real CORS header names are context suppressors; custom secret-bearing names must surface"
    );
}

#[test]
fn false_positive_context_detects_http_cache_header() {
    let lines = vec![r#"ETag: W/concat!("xox", "b-8f3a9b2c1d4e5f60718293a4b5c6d7e8f9a0b")"#];
    assert!(is_false_positive_context(&lines, 0, None));
}

#[test]
fn false_positive_match_context_detects_http_cache_header() {
    let text = r#"ETag: W/concat!("xox", "b-8f3a9b2c1d4e5f60718293a4b5c6d7e8f9a0b")"#;
    let offset = text.find("xox").expect("fixture contains header token");
    assert!(is_false_positive_match_context(text, offset, None));
}

#[test]
fn false_positive_context_does_not_suppress_adjacent_etag_metadata() {
    let lines = vec![
        r#""etag": "v1","#,
        r#""api_key": "sk-proj-abcdefghijklmnopqrstuvwxyz123456""#,
    ];
    assert!(
        !is_false_positive_context(&lines, 1, None),
        "an adjacent JSON etag field is not an HTTP ETag header and must not hide a secret"
    );
}

#[test]
fn false_positive_context_does_not_suppress_adjacent_unquoted_etag_metadata() {
    let lines = vec![
        "etag: v1",
        "api_key = sk-proj-abcdefghijklmnopqrstuvwxyz123456",
    ];
    assert!(
        !is_false_positive_context(&lines, 1, None),
        "an adjacent unquoted etag metadata key is not an HTTP ETag header for the secret line"
    );
}

#[test]
fn false_positive_match_context_does_not_suppress_adjacent_etag_metadata() {
    let text = "etag: v1\napi_key = sk-proj-abcdefghijklmnopqrstuvwxyz123456\n";
    let offset = text.find("sk-proj").expect("fixture contains secret");
    assert!(
        !is_false_positive_match_context(text, offset, None),
        "match-window checks must not let adjacent etag metadata hide the current secret line"
    );
}
