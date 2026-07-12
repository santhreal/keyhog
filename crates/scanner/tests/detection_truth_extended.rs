//! Extended end-to-end detection-truth (#177/#184): more vendor detectors plus
//! the ENCODED and STRUCTURED paths — a secret hidden in a base64 blob must be
//! decoded and re-scanned, and a secret inside JSON must be found. Exact-value
//! assertions (Law 6). Strong-anchor/decoder paths are ML-independent, so these
//! hold with or without the `ml` feature (run without `ml` while the embedded
//! weights are mid-retrain — see BACKLOG ml-weights finding).

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn scan_credentials(text: &str) -> Vec<String> {
    let detectors = keyhog_core::embedded_detector_specs().to_vec();
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "detection-truth-test".into(),
            path: Some("secrets.txt".into()),
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

fn assert_detects(text: &str, secret: &str) {
    let creds = scan_credentials(text);
    assert!(
        creds.iter().any(|c| c == secret),
        "expected to recover `{secret}` from `{text}`; found: {creds:?}"
    );
}

// ── more vendor detectors ────────────────────────────────────────────────────

#[test]
fn detects_shopify_access_token() {
    assert_detects(
        "shopify = shpat_0123456789abcdef0123456789abcdef",
        "shpat_0123456789abcdef0123456789abcdef",
    );
}

#[test]
fn detects_npm_access_token() {
    assert_detects(
        "//registry.npmjs.org/:_authToken=npm_0123456789abcdefghijklmnopqrstuvwxyzAB",
        "npm_0123456789abcdefghijklmnopqrstuvwxyzAB",
    );
}

#[test]
fn detects_square_access_token() {
    assert_detects(
        "square = sq0atp-0123456789abcdefghijkl",
        "sq0atp-0123456789abcdefghijkl",
    );
}

#[test]
fn detects_mailgun_api_key() {
    assert_detects(
        "MAILGUN=key-0123456789abcdef0123456789abcdef",
        "key-0123456789abcdef0123456789abcdef",
    );
}

#[test]
fn detects_json_web_token() {
    assert_detects(
        "auth: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcDEF123456",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcDEF123456",
    );
}

// ── encoded + structured paths ───────────────────────────────────────────────

#[test]
fn recovers_aws_key_from_a_base64_encoded_blob() {
    // "QUtJQVFZTFBNTjVIRklRUjdCQkI=" is base64 for "AKIAQYLPMN5HFIQR7BBB".
    // The decode-and-rescan pipeline must decode it and surface the AWS key.
    assert_detects(
        "payload = QUtJQVFZTFBNTjVIRklRUjdCQkI=",
        "AKIAQYLPMN5HFIQR7BBB",
    );
}

#[test]
fn recovers_aws_key_embedded_in_json() {
    assert_detects(
        "{\"aws_key\": \"AKIAQYLPMN5HFIQR7BBB\", \"region\": \"us-east-1\"}",
        "AKIAQYLPMN5HFIQR7BBB",
    );
}
