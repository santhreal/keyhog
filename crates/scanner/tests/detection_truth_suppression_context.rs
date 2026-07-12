//! Detection-truth for SUPPRESSION + context + multiline (#177/#184).
//!
//! The positive suite proves secrets are found; these prove the precision side:
//! documented-example and obvious-placeholder tokens are NOT flagged, low-signal
//! strings are ignored, and real secrets are still recovered across config
//! formats and multi-line PEM blocks. Heuristic suppression + entropy gating +
//! multiline stitching are ML-independent, so these hold with/without `ml` (run
//! without `ml` while the embedded weights are mid-retrain).

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn scan_credentials(text: &str, path: &str) -> Vec<String> {
    let detectors = keyhog_core::embedded_detector_specs().to_vec();
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "detection-truth-test".into(),
            path: Some(path.into()),
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

// ── suppression truth (precision) ────────────────────────────────────────────

#[test]
fn suppresses_the_aws_canonical_example_key() {
    // AKIAIOSFODNN7EXAMPLE is AWS's documented placeholder — must never flag.
    let creds = scan_credentials("key = AKIAIOSFODNN7EXAMPLE", "s.txt");
    assert!(
        !creds.iter().any(|c| c == "AKIAIOSFODNN7EXAMPLE"),
        "AWS canonical example key must be suppressed; found: {creds:?}"
    );
}

#[test]
fn suppresses_an_obvious_placeholder_key() {
    let creds = scan_credentials("key = AKIAXXXXXXXXXXXXXXXX", "s.txt");
    assert!(
        !creds.iter().any(|c| c == "AKIAXXXXXXXXXXXXXXXX"),
        "an all-X placeholder must be suppressed; found: {creds:?}"
    );
}

#[test]
fn ignores_a_low_entropy_repeated_string() {
    let creds = scan_credentials("token = aaaaaaaaaaaaaaaaaaaaaaaa", "s.txt");
    assert!(
        creds.is_empty(),
        "a low-entropy repeated string must not be flagged; found: {creds:?}"
    );
}

// ── real secrets across config formats (context) ─────────────────────────────

#[test]
fn detects_aws_key_in_a_dotenv_file() {
    let creds = scan_credentials("AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7BBB", ".env");
    assert!(
        creds.iter().any(|c| c == "AKIAQYLPMN5HFIQR7BBB"),
        "found: {creds:?}"
    );
}

#[test]
fn detects_aws_key_in_a_yaml_file() {
    let creds = scan_credentials("aws_key: AKIAQYLPMN5HFIQR7BBB", "config.yml");
    assert!(
        creds.iter().any(|c| c == "AKIAQYLPMN5HFIQR7BBB"),
        "found: {creds:?}"
    );
}

#[test]
fn detects_a_real_secret_even_in_a_code_comment() {
    // A real key in a comment is still a leak; it must be flagged.
    let creds = scan_credentials("// key: AKIAQYLPMN5HFIQR7BBB", "s.rs");
    assert!(
        creds.iter().any(|c| c == "AKIAQYLPMN5HFIQR7BBB"),
        "found: {creds:?}"
    );
}

// ── multiline stitching ──────────────────────────────────────────────────────

#[test]
fn recovers_a_multiline_rsa_private_key_block() {
    let pem = "-----BEGIN RSA PRIVATE KEY-----\n\
               MIIEpAIBAAKCAQEA1234567890abcdefGHIJKLMNOPqrstuvwxyz+/ABCDEF01234\n\
               MIIEpAIBAAKCAQEA1234567890abcdefGHIJKLMNOPqrstuvwxyz+/ABCDEF01234\n\
               -----END RSA PRIVATE KEY-----";
    let creds = scan_credentials(pem, "id_rsa");
    // The multiline detector stitches the whole block (markers + body) into one
    // credential spanning the newlines.
    assert!(
        creds.iter().any(|c| {
            c.contains("BEGIN RSA PRIVATE KEY")
                && c.contains("END RSA PRIVATE KEY")
                && c.contains("MIIEpAIBAAKCAQEA")
        }),
        "the full multi-line RSA private-key block must be recovered; found: {creds:?}"
    );
}
