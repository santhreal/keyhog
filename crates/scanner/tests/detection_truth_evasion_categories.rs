//! Detection-truth: unicode-EVASION category coverage (#177/#184, vector #2).
//! Beyond ZWSP/fullwidth (covered elsewhere), attackers hide secrets behind
//! combining marks, zero-width joiners, word joiners, soft hyphens, invisible
//! math operators, bidi overrides, tag characters, and homoglyphs. keyhog's
//! unicode-hardening pass must fold every category back to the clean credential
//! before matching. Each test plants a known AWS key behind one category and
//! asserts recovery (Law 6). A red here is an evasion-gap FINDING, not a flaky
//! test. ML-independent (normalization precedes scoring); run without `ml` while
//! weights are mid-retrain.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

const AWS: &str = "AKIAQYLPMN5HFIQR7BBB";

fn scan_credentials(text: &str) -> Vec<String> {
    let detectors = keyhog_core::embedded_detector_specs().to_vec();
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "evasion-category-test".into(),
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

fn assert_recovers_aws(obfuscated: &str) {
    let creds = scan_credentials(obfuscated);
    assert!(
        creds.iter().any(|c| c == AWS),
        "evasion not defeated: expected `{AWS}`; found: {creds:?} for input {obfuscated:?}"
    );
}

#[test]
fn zero_width_joiner_mid_token() {
    assert_recovers_aws("key = AKIA\u{200D}QYLPMN5HFIQR7BBB");
}

#[test]
fn zero_width_non_joiner_mid_token() {
    assert_recovers_aws("key = AKIAQYLP\u{200C}MN5HFIQR7BBB");
}

#[test]
fn word_joiner_mid_token() {
    assert_recovers_aws("key = AKIA\u{2060}QYLPMN5HFIQR7BBB");
}

#[test]
fn soft_hyphen_mid_token() {
    assert_recovers_aws("key = AKIAQYLPMN\u{00AD}5HFIQR7BBB");
}

#[test]
fn invisible_times_mid_token() {
    // U+2062 INVISIBLE TIMES — an invisible math operator.
    assert_recovers_aws("key = AKIAQ\u{2062}YLPMN5HFIQR7BBB");
}

#[test]
fn function_application_mid_token() {
    // U+2061 FUNCTION APPLICATION.
    assert_recovers_aws("key = AKIAQYLPMN5H\u{2061}FIQR7BBB");
}

#[test]
fn byte_order_mark_mid_token() {
    // U+FEFF ZERO WIDTH NO-BREAK SPACE / BOM.
    assert_recovers_aws("key = AKIAQYL\u{FEFF}PMN5HFIQR7BBB");
}

#[test]
fn bidi_rlo_wrapped_token() {
    // U+202E RIGHT-TO-LEFT OVERRIDE ... U+202C POP DIRECTIONAL FORMATTING.
    assert_recovers_aws("key = \u{202E}AKIAQYLPMN5HFIQR7BBB\u{202C}");
}
