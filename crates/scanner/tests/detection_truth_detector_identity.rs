//! Detection-truth: full finding IDENTITY (#177/#184). Beyond the recovered
//! value, a finding must name the RIGHT detector, service, severity, and byte
//! offset, what a report/SARIF consumer keys on. Asserts all of them (Law 6:
//! rule + credential + location). ML-independent named detectors; run without
//! `ml` while the embedded weights are mid-retrain.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::{LazyLock, Mutex};

static SCANNER: LazyLock<Mutex<CompiledScanner>> = LazyLock::new(|| {
    Mutex::new(
        CompiledScanner::compile(keyhog_core::embedded_detector_specs().to_vec())
            .expect("scanner compile"),
    )
});

struct Found {
    detector_id: String,
    service: String,
    severity: String,
    offset: usize,
    credential: String,
}

fn scan(text: &str) -> Vec<Found> {
    let scanner = SCANNER.lock().expect("identity scanner lock");
    scanner.clear_fragment_cache();
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

/// Assert some finding matches the full expected identity tuple.
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

#[test]
fn aws_access_key_full_identity() {
    assert_identity(
        "key = AKIAQYLPMN5HFIQR7BBB",
        "aws-access-key",
        "aws",
        "Critical",
        6,
        "AKIAQYLPMN5HFIQR7BBB",
    );
}

#[test]
fn gitlab_pat_full_identity() {
    assert_identity(
        "t = glpat-ABCDEF1234567890abcd",
        "gitlab-personal-access-token",
        "gitlab",
        "Critical",
        4,
        "glpat-ABCDEF1234567890abcd",
    );
}

#[test]
fn slack_bot_full_identity() {
    assert_identity(
        "t = xoxb-2345678901234-2345678901234-AbCdEfGhIjKlMnOpQrStUvWx",
        "slack-bot-token",
        "slack",
        "Critical",
        4,
        "xoxb-2345678901234-2345678901234-AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn google_api_key_full_identity() {
    assert_identity(
        "key=AIzaSyA1234567890abcdefghijklmnopqrstuv",
        "google-api-key",
        "google",
        "Critical",
        4,
        "AIzaSyA1234567890abcdefghijklmnopqrstuv",
    );
}

#[test]
fn stripe_secret_key_full_identity() {
    assert_identity(
        "k=sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000",
        "stripe-secret-key",
        "stripe",
        "Critical",
        2,
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000",
    );
}
