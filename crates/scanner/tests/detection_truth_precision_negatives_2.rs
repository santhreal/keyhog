//! Detection-truth: PRECISION negatives, batch 2 (#177/#184). The bench win over
//! peers is precision (never flagging hashes, IDs, examples, or placeholders).
//! Each input is a verified non-secret that the no-ml (heuristic) path already
//! suppresses; since the no-ml path is strictly MORE permissive than the ml path
//! (ml only removes candidates), a negative that holds here holds under `ml` too.
//! Run without `ml` while the embedded weights are mid-retrain. (The one classic
//! that DOES slip through the heuristic path, a semver build-metadata string 
//! is tracked as the entropy-token-semver-FP finding, not asserted here.)

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn scan_credentials(text: &str) -> Vec<String> {
    let detectors = keyhog_core::embedded_detector_specs().to_vec();
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "precision-neg-test".into(),
            path: Some("s.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .iter()
        .flat_map(|per_chunk| per_chunk.iter())
        .map(|m| m.credential.as_ref().to_string())
        .collect()
}

fn assert_no_finding(text: &str) {
    let creds = scan_credentials(text);
    assert!(
        creds.is_empty(),
        "no credential must be reported for `{text}`; found: {creds:?}"
    );
}

#[test]
fn ignores_aws_docs_example_access_key_id() {
    // The canonical AWS documentation example key (a must-suppress).
    assert_no_finding("aws_access_key_id = AKIAIOSFODNN7EXAMPLE");
}

#[test]
fn ignores_aws_docs_example_secret_key() {
    assert_no_finding("aws_secret = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
}

#[test]
fn ignores_a_git_commit_sha() {
    assert_no_finding("commit = 356a192b7913b04c54574d18c28d46e6395428ab");
}

#[test]
fn ignores_an_md5_hash() {
    assert_no_finding("hash = 5d41402abc4b2a76b9719d911017c592");
}

#[test]
fn ignores_a_sha256_digest() {
    assert_no_finding("digest = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

#[test]
fn ignores_a_uuid() {
    assert_no_finding("id = 550e8400-e29b-41d4-a716-446655440000");
}

#[test]
fn ignores_base64_of_plain_text() {
    // base64("hello world") (decodes to non-secret text).
    assert_no_finding("data = aGVsbG8gd29ybGQ=");
}

#[test]
fn ignores_lorem_ipsum() {
    assert_no_finding("text = Lorem ipsum dolor sit amet consectetur");
}

#[test]
fn ignores_a_unix_file_path() {
    assert_no_finding("path = /usr/local/bin/some-very-long-binary-name-here");
}

#[test]
fn ignores_a_named_replace_me_placeholder() {
    assert_no_finding("token = YOUR_TOKEN_HERE_REPLACE_ME_1234567890");
}

#[test]
fn ignores_an_all_x_placeholder() {
    assert_no_finding("key = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn ignores_a_repeating_hex_placeholder() {
    assert_no_finding("secret = deadbeefdeadbeefdeadbeefdeadbeef");
}

#[test]
fn ignores_an_npm_semver_range() {
    assert_no_finding("dep = ^1.0.0 || >=2.0.0 <3.0.0");
}
