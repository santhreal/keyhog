//! Wire the dead `tests/data/corpus/evasion/*` fixtures into `cargo test`.
//!
//! Per the internal design notes, eight evasion fixtures
//! shipped under `tests/data/corpus/evasion/` but had no strict Rust coverage.
//! Each evasion class gets a **positive** (real planted secret must fire) and a
//! **negative twin** (same transport shape, known-example fake must not surface).
//!
//! CLAUDE.md anti-rigging rule: every positive names an expected credential
//! substring - a function returning `Vec::new()` fails.

use super::corpus_support::{
    corpus_fixture_path, has_credential, has_detector, production_scanner, scan_corpus, scan_text,
    AWS_ACCESS_KEY, GITHUB_PAT,
};
use keyhog_core::{Chunk, ChunkMetadata};

/// OpenAI project key planted across evasion fixtures.
pub const OPENAI_PROJ_KEY: &str =
    "sk-proj-abcDEF123_def-456GHI789jkl-MNO012pqr-STU345vwx-YZA678bcd_efghi";

/// Known-example credentials the engine must suppress (negative twins).
pub const FAKE_AWS_EXAMPLE: &str = concat!("AK", "IAIOSFODNN7EXAMPLE");
pub const FAKE_GITHUB_EXAMPLE: &str = "ghp_example_0001_xxxxxxxxxxxxxxxxxxxx";

const EVASION: &str = "evasion";

fn scan_fixture(rel: &str) -> Vec<keyhog_core::RawMatch> {
    scan_corpus(EVASION, rel)
}

fn assert_detected(matches: &[keyhog_core::RawMatch], fixture: &str, credential: &str) {
    assert!(
        has_credential(matches, credential),
        "{fixture}: expected credential {credential:?}; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

fn assert_not_detected(matches: &[keyhog_core::RawMatch], fixture: &str, credential: &str) {
    assert!(
        !has_credential(matches, credential),
        "{fixture}: negative twin {credential:?} must not be flagged; matches={:?}",
        matches
            .iter()
            .map(|m| m.credential.as_ref())
            .collect::<Vec<_>>()
    );
}

fn assert_any_service(matches: &[keyhog_core::RawMatch], fixture: &str, services: &[&str]) {
    let hit = services.iter().any(|needle| has_detector(matches, needle));
    assert!(
        hit,
        "{fixture}: expected at least one of {:?} to fire; got {} matches: {:?}",
        services,
        matches.len(),
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.service.as_ref()))
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// url_encoded.txt - percent-encoded credential fragments
// ---------------------------------------------------------------------------

#[test]
fn evasion_url_encoded_detects_aws_access_key() {
    let matches = scan_fixture("url_encoded.txt");
    assert_detected(&matches, "url_encoded.txt", AWS_ACCESS_KEY);
    assert_any_service(&matches, "url_encoded.txt", &["aws"]);
}

#[test]
fn evasion_url_encoded_negative_twin_suppresses_example_aws() {
    // Same URL-encoding transport, but the AWS EXAMPLE credential must stay suppressed.
    let twin = "aws=%41%4b%49%41%49%4f%53%46%4f%44%4e%4e%37%45%58%41%4d%50%4c%45\n";
    let matches = scan_text(twin, "evasion/url_encoded_negative.txt");
    assert_not_detected(&matches, "url_encoded negative twin", FAKE_AWS_EXAMPLE);
}

// ---------------------------------------------------------------------------
// base64_wrapped.json - base64-wrapped OpenAI project key
// ---------------------------------------------------------------------------

#[test]
fn evasion_base64_wrapped_detects_openai_proj_key() {
    let matches = scan_fixture("base64_wrapped.json");
    assert_detected(&matches, "base64_wrapped.json", OPENAI_PROJ_KEY);
    assert_any_service(&matches, "base64_wrapped.json", &["openai"]);
}

#[test]
fn evasion_base64_wrapped_negative_twin_suppresses_example_aws() {
    // Base64 of AKIAIOSFODNN7EXAMPLE - same wrap shape, known dummy must not fire.
    let twin = r#"{"config": "QUtJQUlPU0ZPRE5ON0VYQU1QTEU="}"#;
    let matches = scan_text(twin, "evasion/base64_wrapped_negative.json");
    assert_not_detected(&matches, "base64_wrapped negative twin", FAKE_AWS_EXAMPLE);
}

// ---------------------------------------------------------------------------
// split_across_lines.py - string concatenation reassembly
// ---------------------------------------------------------------------------

#[test]
fn evasion_split_across_lines_detects_aws_access_key() {
    let matches = scan_fixture("split_across_lines.py");
    assert_detected(&matches, "split_across_lines.py", AWS_ACCESS_KEY);
    assert_any_service(&matches, "split_across_lines.py", &["aws"]);
}

#[test]
fn evasion_split_across_lines_negative_twin_suppresses_example_aws() {
    let twin = "\
aws_a = \"AKIA\"
aws_b = \"IOSFODNN7EXAMPLE\"
aws_key = aws_a + aws_b
";
    let matches = scan_text(twin, "evasion/split_across_lines_negative.py");
    assert_not_detected(
        &matches,
        "split_across_lines negative twin",
        FAKE_AWS_EXAMPLE,
    );
}

// ---------------------------------------------------------------------------
// multiline_json.json - secrets embedded in JSON values
// ---------------------------------------------------------------------------

#[test]
fn evasion_multiline_json_detects_github_pat() {
    let matches = scan_fixture("multiline_json.json");
    assert_detected(&matches, "multiline_json.json", GITHUB_PAT);
    assert_any_service(&matches, "multiline_json.json", &["github"]);
}

#[test]
fn evasion_multiline_json_negative_twin_suppresses_example_github() {
    let twin = r#"{"api_key": "ghp_example_0001_xxxxxxxxxxxxxxxxxxxx"}"#;
    let matches = scan_text(twin, "evasion/multiline_json_negative.json");
    assert_not_detected(
        &matches,
        "multiline_json negative twin",
        FAKE_GITHUB_EXAMPLE,
    );
}

// ---------------------------------------------------------------------------
// hex_encoded.js - hex-encoded OpenAI project key
// ---------------------------------------------------------------------------

#[test]
fn evasion_hex_encoded_detects_openai_proj_key() {
    let matches = scan_fixture("hex_encoded.js");
    assert_detected(&matches, "hex_encoded.js", OPENAI_PROJ_KEY);
    assert_any_service(&matches, "hex_encoded.js", &["openai"]);
}

#[test]
fn evasion_hex_encoded_negative_twin_suppresses_example_aws() {
    // Hex of AKIAIOSFODNN7EXAMPLE
    let twin = "const h = \"414b4941494f53464f444e4e374558414d504c45\";\n";
    let matches = scan_text(twin, "evasion/hex_encoded_negative.js");
    assert_not_detected(&matches, "hex_encoded negative twin", FAKE_AWS_EXAMPLE);
}

// ---------------------------------------------------------------------------
// variable_indirection.rb - prefix/suffix variable concatenation
// ---------------------------------------------------------------------------

#[test]
fn evasion_variable_indirection_detects_github_pat_and_aws() {
    let matches = scan_fixture("variable_indirection.rb");
    assert_detected(&matches, "variable_indirection.rb", GITHUB_PAT);
    assert_detected(&matches, "variable_indirection.rb", AWS_ACCESS_KEY);
}

#[test]
fn evasion_variable_indirection_negative_twin_suppresses_example_github() {
    let twin = "\
prefix = \"ghp_\"
suffix = \"example_0001_xxxxxxxxxxxxxxxxxxxx\"
github_token = prefix + suffix
";
    let matches = scan_text(twin, "evasion/variable_indirection_negative.rb");
    assert_not_detected(
        &matches,
        "variable_indirection negative twin",
        FAKE_GITHUB_EXAMPLE,
    );
}

// ---------------------------------------------------------------------------
// embedded_in_binary.txt - credentials embedded in binary-like noise
// ---------------------------------------------------------------------------

#[test]
fn evasion_embedded_in_binary_detects_github_pat_and_aws() {
    let matches = scan_fixture("embedded_in_binary.txt");
    assert_detected(&matches, "embedded_in_binary.txt", GITHUB_PAT);
    assert_detected(&matches, "embedded_in_binary.txt", AWS_ACCESS_KEY);
}

#[test]
fn evasion_embedded_in_binary_negative_twin_suppresses_example_credentials() {
    let twin = "BINARYHEADER\\x00\\x01\\x02\\x03ghp_example_0001_xxxxxxxxxxxxxxxxxxxx\\x00\\xFF\\xFEAKIAIOSFODNN7EXAMPLE\\x00TRAILER\n";
    let matches = scan_text(twin, "evasion/embedded_in_binary_negative.txt");
    assert_not_detected(
        &matches,
        "embedded_in_binary negative twin",
        FAKE_GITHUB_EXAMPLE,
    );
    assert_not_detected(
        &matches,
        "embedded_in_binary negative twin",
        FAKE_AWS_EXAMPLE,
    );
}

// ---------------------------------------------------------------------------
// reversed_strings.py - reversed credential literals (decode feature)
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "decode")]
fn evasion_reversed_strings_detects_reversed_aws_access_key() {
    let matches = scan_fixture("reversed_strings.py");
    assert_detected(&matches, "reversed_strings.py", AWS_ACCESS_KEY);
    assert_any_service(&matches, "reversed_strings.py", &["aws"]);
}

#[test]
#[cfg(feature = "decode")]
fn evasion_reversed_strings_negative_twin_suppresses_forward_example_aws() {
    // The fixture embeds a forward EXAMPLE AWS key; suppression must hold even
    // when the literal is visible without decode.
    let matches = scan_fixture("reversed_strings.py");
    assert_not_detected(&matches, "reversed_strings.py", FAKE_AWS_EXAMPLE);
    assert_not_detected(&matches, "reversed_strings.py", FAKE_GITHUB_EXAMPLE);
}

// ---------------------------------------------------------------------------
// Synthetic: two-fragment AWS concat without shared prefix (multiline feature)
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "multiline")]
fn evasion_engine_reassembles_two_fragment_aws_without_shared_prefix() {
    let synthetic = "\
key_head = 'AKIA'
key_tail = 'R7VXNPLMQ3HSKWJT'
aws_access = key_head + key_tail
unrelated = 'foo' + 'bar'
";
    let chunk = Chunk {
        data: synthetic.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "test/synthetic".into(),
            path: Some("synthetic.py".into()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
            ..Default::default()
        },
    };
    let matches = production_scanner().scan(&chunk);
    assert_detected(&matches, "synthetic two-fragment AWS", AWS_ACCESS_KEY);
}

// ---------------------------------------------------------------------------
// Inventory: every file under corpus/evasion must be referenced
// ---------------------------------------------------------------------------

#[test]
fn evasion_corpus_files_exist_on_disk() {
    let expected = [
        "url_encoded.txt",
        "base64_wrapped.json",
        "split_across_lines.py",
        "multiline_json.json",
        "hex_encoded.js",
        "variable_indirection.rb",
        "embedded_in_binary.txt",
        "reversed_strings.py",
    ];
    for rel in expected {
        let path = corpus_fixture_path(EVASION, rel);
        assert!(
            path.is_file(),
            "evasion fixture missing: {}",
            path.display()
        );
    }
}

#[test]
fn evasion_full_file_scan_uses_production_scanner() {
    let fixtures = [
        "url_encoded.txt",
        "base64_wrapped.json",
        "split_across_lines.py",
        "multiline_json.json",
        "hex_encoded.js",
        "variable_indirection.rb",
        "embedded_in_binary.txt",
        "reversed_strings.py",
    ];
    let scanner = production_scanner();
    for rel in fixtures {
        let path = corpus_fixture_path(EVASION, rel);
        let data = std::fs::read_to_string(&path).expect("read fixture");
        let chunk = Chunk {
            data: data.into(),
            metadata: ChunkMetadata {
                base_offset: 0,
                base_line: 0,
                source_type: format!("test/corpus/{EVASION}").into(),
                path: Some(path.display().to_string().into()),
                commit: None,
                author: None,
                date: None,
                mtime_ns: None,
                size_bytes: None,
                ..Default::default()
            },
        };
        let _ = scanner.scan(&chunk);
    }
}
