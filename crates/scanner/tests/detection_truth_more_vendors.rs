//! Detection-truth: additional vendor detectors (#177/#184). Exact-value
//! recovery through the public scan API (Law 6). Strong-anchor named detectors +
//! structural URL parsing → ML-independent, valid with/without `ml` (run without
//! `ml` while the embedded weights are mid-retrain).

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

#[test]
fn detects_huggingface_token() {
    let t = "hf_0123456789abcdefghijklmnopqrstuvwxyz";
    assert_detects(&format!("HF_TOKEN={t}"), t);
}

#[test]
fn detects_slack_user_token() {
    let t = "xoxp-2345678901234-2345678901234-2345678901234-abcdef0123456789abcdef0123456789";
    assert_detects(&format!("slack = {t}"), t);
}

#[test]
fn detects_slack_app_level_token() {
    let t = "xapp-1-A01234567AB-1234567890123-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab";
    assert_detects(&format!("slack = {t}"), t);
}

#[test]
fn detects_google_oauth_client_secret() {
    let t = "GOCSPX-0123456789abcdefghijklmnopqr";
    assert_detects(&format!("client_secret = {t}"), t);
}

#[test]
fn extracts_the_password_from_a_mongodb_srv_uri() {
    assert_detects(
        "mongodb+srv://dbuser:dbp4ss@cluster0.abcde.mongodb.net/test",
        "dbp4ss",
    );
}
