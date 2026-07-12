//! Detection-truth: full finding IDENTITY for more vendors + SEVERITY variety
//! (#177/#184). Extends the identity suite; includes High-severity detectors
//! (Postman/HuggingFace/Square) so severity mapping is pinned, not assumed
//! uniform. Law 6 (rule + service + severity + offset + credential).
//! ML-independent; run without `ml` while the embedded weights are mid-retrain.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

struct Found {
    detector_id: String,
    service: String,
    severity: String,
    offset: usize,
    credential: String,
}

fn scan(text: &str) -> Vec<Found> {
    let detectors = keyhog_core::embedded_detector_specs().to_vec();
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "detection-truth-test".into(),
            path: Some("s.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .iter()
        .flat_map(|per_chunk| per_chunk.iter())
        .map(|m| Found {
            detector_id: m.detector_id.to_string(),
            service: m.service.to_string(),
            severity: format!("{:?}", m.severity),
            offset: m.location.offset,
            credential: m.credential.as_ref().to_string(),
        })
        .collect()
}

fn assert_identity(
    text: &str,
    detector_id: &str,
    service: &str,
    severity: &str,
    offset: usize,
    credential: &str,
) {
    let found = scan(text);
    assert!(
        found.iter().any(|f| f.detector_id == detector_id
            && f.service == service
            && f.severity == severity
            && f.offset == offset
            && f.credential == credential),
        "no finding matched id={detector_id} service={service} sev={severity} off={offset} \
         cred={credential}; got: {:?}",
        found
            .iter()
            .map(|f| format!(
                "(id={} svc={} sev={} off={} cred={})",
                f.detector_id, f.service, f.severity, f.offset, f.credential
            ))
            .collect::<Vec<_>>()
    );
}

// ── Critical-severity detectors ──────────────────────────────────────────────

#[test]
fn shopify_admin_token_identity() {
    assert_identity(
        "t = shpat_0123456789abcdef0123456789abcdef",
        "shopify-admin-api-token",
        "shopify",
        "Critical",
        4,
        "shpat_0123456789abcdef0123456789abcdef",
    );
}

#[test]
fn npm_access_token_identity() {
    assert_identity(
        "t = npm_0123456789abcdefghijklmnopqrstuvwxyzAB",
        "npm-access-token",
        "npm",
        "Critical",
        4,
        "npm_0123456789abcdefghijklmnopqrstuvwxyzAB",
    );
}

#[test]
fn discord_bot_token_identity() {
    assert_identity(
        "t = MTE2MjkzNDU2Nzg5MDEyMzQ1Ng.GxYzAb.abcdefghijklmnopqrstuvwxyz01234",
        "discord-bot-token",
        "discord",
        "Critical",
        4,
        "MTE2MjkzNDU2Nzg5MDEyMzQ1Ng.GxYzAb.abcdefghijklmnopqrstuvwxyz01234",
    );
}

#[test]
fn mailgun_api_key_identity() {
    assert_identity(
        "t = key-0123456789abcdef0123456789abcdef",
        "mailgun-api-key",
        "mailgun",
        "Critical",
        4,
        "key-0123456789abcdef0123456789abcdef",
    );
}

#[test]
fn github_oauth_token_identity() {
    assert_identity(
        "t = gho_0123456789abcdef0123456789abcdef0123",
        "github-oauth-access-token",
        "github",
        "Critical",
        4,
        "gho_0123456789abcdef0123456789abcdef0123",
    );
}

#[test]
fn google_oauth_client_secret_identity() {
    assert_identity(
        "t = GOCSPX-0123456789abcdefghijklmnopqr",
        "google-oauth-client-secret",
        "google",
        "Critical",
        4,
        "GOCSPX-0123456789abcdefghijklmnopqr",
    );
}

// ── High-severity detectors (severity mapping is NOT uniform) ─────────────────

#[test]
fn postman_api_key_is_high_severity() {
    assert_identity(
        "t = PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123",
        "postman-api-key",
        "postman",
        "High",
        4,
        "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123",
    );
}

#[test]
fn square_access_token_is_high_severity() {
    assert_identity(
        "t = sq0atp-0123456789abcdefghijkl",
        "square-access-token",
        "square",
        "High",
        4,
        "sq0atp-0123456789abcdefghijkl",
    );
}

#[test]
fn huggingface_token_is_high_severity() {
    assert_identity(
        "t = hf_0123456789abcdefghijklmnopqrstuvwxyz",
        "huggingface-api-key",
        "huggingface",
        "High",
        4,
        "hf_0123456789abcdefghijklmnopqrstuvwxyz",
    );
}
