//! Detection-truth: more vendor tokens + an EVASION defeat (#177/#184).
//!
//! Exact-value assertions (Law 6) through the public scan API. The headline is
//! the homoglyph case: a Cyrillic-`А` obfuscated AWS key must be normalized to
//! ASCII and detected — proving the unicode-hardening pass on the scan path.
//! ML-independent (regex/structural/normalization), so valid with/without `ml`
//! (run without `ml` while the embedded weights are mid-retrain).

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

// ── EVASION: homoglyph normalization ─────────────────────────────────────────

#[test]
fn normalizes_a_cyrillic_homoglyph_and_detects_the_aws_key() {
    // U+0410 (Cyrillic Capital A) replaces the leading ASCII 'A'. The scan path's
    // unicode-hardening must fold it so the AWS detector still fires on ASCII.
    let obfuscated = "key = \u{0410}KIAQYLPMN5HFIQR7BBB";
    assert_detects(obfuscated, "AKIAQYLPMN5HFIQR7BBB");
}

// ── more vendor tokens ───────────────────────────────────────────────────────

#[test]
fn detects_discord_bot_token() {
    let t = "MTE2MjkzNDU2Nzg5MDEyMzQ1Ng.GxYzAb.abcdefghijklmnopqrstuvwxyz01234";
    assert_detects(&format!("DISCORD={t}"), t);
}

#[test]
fn detects_postman_api_key() {
    let t = "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123";
    assert_detects(&format!("POSTMAN={t}"), t);
}

#[test]
fn detects_github_oauth_token() {
    let t = "gho_0123456789abcdef0123456789abcdef0123";
    assert_detects(&format!("GH={t}"), t);
}

#[test]
fn detects_github_refresh_token() {
    let t = "ghr_0123456789abcdef0123456789abcdef0123";
    assert_detects(&format!("GH={t}"), t);
}

#[test]
fn detects_github_server_token() {
    let t = "ghs_0123456789abcdef0123456789abcdef0123";
    assert_detects(&format!("GH={t}"), t);
}

// ── credential embedded in a URL ─────────────────────────────────────────────

#[test]
fn extracts_the_password_from_a_basic_auth_url() {
    assert_detects("https://user:p4ssw0rd123@example.com/path", "p4ssw0rd123");
}
