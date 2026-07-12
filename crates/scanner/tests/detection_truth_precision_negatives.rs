//! Detection-truth: PRECISION negatives (#177/#184). The bench win over peers is
//! precision — not flagging placeholders, examples, and non-secrets. Each input
//! is a known non-secret; the scan must yield NO credential. These are robust
//! across feature sets: the no-ml scan path is strictly MORE permissive than the
//! ml path (ML only removes candidates), so a negative that holds here holds
//! under `ml` too (run without `ml` while the embedded weights are mid-retrain).

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn scan_credentials(text: &str) -> Vec<String> {
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
fn ignores_a_named_placeholder_value() {
    assert_no_finding("api_key = your_api_key_here");
}

#[test]
fn ignores_an_angle_bracket_placeholder() {
    assert_no_finding("api_key = <your-api-key>");
}

#[test]
fn ignores_a_changeme_password() {
    assert_no_finding("password = changeme");
}

#[test]
fn ignores_an_all_zeros_secret() {
    assert_no_finding("secret = 00000000000000000000000000000000");
}

#[test]
fn ignores_an_example_email_address() {
    assert_no_finding("contact = test@example.com");
}

#[test]
fn ignores_a_redacted_marker() {
    assert_no_finding("token = <REDACTED>");
}

#[test]
fn ignores_a_google_key_shaped_example() {
    assert_no_finding("key = AIzaSyEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMP");
}

#[test]
fn ignores_a_stripe_placeholder_key() {
    assert_no_finding("stripe = sk_test_your_stripe_key_here_000000");
}
