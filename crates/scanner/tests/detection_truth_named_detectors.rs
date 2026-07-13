//! End-to-end detection-truth through the public scan API (#177/#184).
//!
//! Feeds canonical secrets into the REAL compile->scan pipeline and asserts the
//! EXACT credential value recovered (Law 6, never `!is_empty`). These target
//! strong-anchor NAMED detectors (regex + checksum), which fire independently of
//! the ML re-scoring layer, so they hold across feature sets. Run without the
//! `ml` feature while the embedded weights are mid-retrain; they also hold under
//! `ml` once the scan path is restored (see BACKLOG ml-weights finding).

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn scan_credentials(text: &str, backend: ScanBackend) -> Vec<String> {
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
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), backend)
        .iter()
        .flat_map(|per_chunk| per_chunk.iter())
        .map(|m| m.credential.as_ref().to_string())
        .collect()
}

/// Assert the exact `secret` is among the credentials recovered from `text`.
fn assert_detects(text: &str, secret: &str) {
    let creds = scan_credentials(text, ScanBackend::CpuFallback);
    assert!(
        creds.iter().any(|c| c == secret),
        "expected to recover `{secret}` from `{text}`; found: {creds:?}"
    );
}

// ── positive detection: exact value recovered ────────────────────────────────

#[test]
fn detects_aws_access_key_id() {
    assert_detects(
        "const KEY = \"AKIAQYLPMN5HFIQR7BBB\";",
        "AKIAQYLPMN5HFIQR7BBB",
    );
}

#[test]
fn detects_aws_temporary_access_key_id() {
    assert_detects("token: ASIAQYLPMN5HFIQR7BBB", "ASIAQYLPMN5HFIQR7BBB");
}

#[test]
fn detects_gitlab_personal_access_token() {
    assert_detects(
        "GITLAB_TOKEN=glpat-ABCDEF1234567890abcd",
        "glpat-ABCDEF1234567890abcd",
    );
}

#[test]
fn detects_slack_bot_token() {
    let t = "xoxb-2345678901234-2345678901234-AbCdEfGhIjKlMnOpQrStUvWx";
    assert_detects(&format!("slack_token = \"{t}\""), t);
}

#[test]
fn detects_google_api_key() {
    assert_detects(
        "key=AIzaSyA1234567890abcdefghijklmnopqrstuv",
        "AIzaSyA1234567890abcdefghijklmnopqrstuv",
    );
}

#[test]
fn detects_stripe_live_secret_key() {
    assert_detects(
        "STRIPE=sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000",
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000",
    );
}

#[test]
fn detects_stripe_test_secret_key() {
    assert_detects(
        "STRIPE=sk_test_4eC39HqLyjWDarjtT1zdp7dc00000000",
        "sk_test_4eC39HqLyjWDarjtT1zdp7dc00000000",
    );
}

#[test]
fn detects_openai_api_key() {
    let t = "sk-ABCDEFGHIJKLMNOPQRSTU3BlbkFJabcdefghijklmnopqrstuv";
    assert_detects(&format!("OPENAI_API_KEY={t}"), t);
}

// ── negative / suppression truth (also ML-independent) ───────────────────────

#[test]
fn rejects_github_token_with_invalid_checksum() {
    // ghp_ tokens carry a CRC32 checksum in the tail; a fabricated one must be
    // rejected, not surfaced (guards the checksum-validation contract).
    let creds = scan_credentials(
        "ghp_016C7f4a8b9D2e3F5a6B7c8D9e0F1a2B3c4D",
        ScanBackend::CpuFallback,
    );
    assert!(
        !creds.iter().any(|c| c.starts_with("ghp_")),
        "an invalid-checksum ghp_ token must not be reported; found: {creds:?}"
    );
}

#[test]
fn does_not_flag_the_aws_documented_example_secret() {
    // AWS's published example secret (…CYEXAMPLEKEY) must not be a finding.
    let creds = scan_credentials(
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ScanBackend::CpuFallback,
    );
    assert!(
        !creds
            .iter()
            .any(|c| c == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        "the AWS documented example secret must not be flagged; found: {creds:?}"
    );
}

#[test]
fn plain_prose_yields_no_credentials() {
    let creds = scan_credentials(
        "The quick brown fox jumps over the lazy dog near the river.",
        ScanBackend::CpuFallback,
    );
    assert!(
        creds.is_empty(),
        "ordinary prose must not produce credentials; found: {creds:?}"
    );
}

// ── multi-secret + backend parity ────────────────────────────────────────────

#[test]
fn recovers_every_secret_in_a_mixed_chunk() {
    let text = "aws = AKIAQYLPMN5HFIQR7BBB\n\
                gcp = AIzaSyA1234567890abcdefghijklmnopqrstuv\n\
                stripe = sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000";
    let creds = scan_credentials(text, ScanBackend::CpuFallback);
    for expected in [
        "AKIAQYLPMN5HFIQR7BBB",
        "AIzaSyA1234567890abcdefghijklmnopqrstuv",
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000",
    ] {
        assert!(
            creds.iter().any(|c| c == expected),
            "mixed chunk must recover `{expected}`; found: {creds:?}"
        );
    }
}

#[test]
fn named_detectors_agree_across_cpu_and_simd_backends() {
    let text = "aws = AKIAQYLPMN5HFIQR7BBB gcp = AIzaSyA1234567890abcdefghijklmnopqrstuv";
    let mut cpu = scan_credentials(text, ScanBackend::CpuFallback);
    let mut simd = scan_credentials(text, ScanBackend::SimdCpu);
    cpu.sort();
    simd.sort();
    assert_eq!(
        cpu, simd,
        "CPU and SIMD backends must recover the same credentials"
    );
    assert!(cpu.iter().any(|c| c == "AKIAQYLPMN5HFIQR7BBB"));
}
