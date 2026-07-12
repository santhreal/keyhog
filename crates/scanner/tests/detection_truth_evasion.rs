//! Detection-truth: EVASION resistance (#177/#184, adversarial vector #2).
//!
//! Attackers obfuscate secrets to slip past scanners. keyhog's unicode-hardening
//! + decode passes must fold these back to the real credential before matching.
//! Each case plants a known AWS/Stripe key behind an obfuscation and asserts the
//! CLEAN value is recovered (Law 6). All ML-independent (normalization/decode
//! run before scoring), so valid with/without `ml` — run without `ml` while the
//! embedded weights are mid-retrain (see BACKLOG ml-weights finding).

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

fn assert_defeats_evasion(obfuscated: &str, real_secret: &str) {
    let creds = scan_credentials(obfuscated);
    assert!(
        creds.iter().any(|c| c == real_secret),
        "evasion must be defeated: expected `{real_secret}`; found: {creds:?}"
    );
}

#[test]
fn strips_a_zero_width_space_inside_an_aws_key() {
    // U+200B ZERO WIDTH SPACE inserted mid-token.
    assert_defeats_evasion("key = AKIA\u{200B}QYLPMN5HFIQR7BBB", "AKIAQYLPMN5HFIQR7BBB");
}

#[test]
fn strips_a_zero_width_space_inside_a_stripe_key() {
    assert_defeats_evasion(
        "k = sk_live_4eC39HqLyjW\u{200B}DarjtT1zdp7dc00000000",
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000",
    );
}

#[test]
fn normalizes_fullwidth_characters_in_an_aws_key() {
    // U+FF21/FF2B/FF29/FF21 = fullwidth A K I A.
    assert_defeats_evasion(
        "key = \u{FF21}\u{FF2B}\u{FF29}\u{FF21}QYLPMN5HFIQR7BBB",
        "AKIAQYLPMN5HFIQR7BBB",
    );
}

#[test]
fn decodes_a_url_percent_encoded_aws_key() {
    // %41%4B%49%41... = "AKIA..." percent-encoded.
    assert_defeats_evasion(
        "v = %41%4B%49%41%51%59%4C%50%4D%4E%35%48%46%49%51%52%37%42%42%42",
        "AKIAQYLPMN5HFIQR7BBB",
    );
}
