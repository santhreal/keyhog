//! Detection-truth: cross-cutting EDGE scenarios (#177/#184) not covered by the
//! per-detector self-validation harness, combined evasion, base64url, multiple
//! distinct secrets, quoting/whitespace, and repeated-occurrence reporting.
//! Exact-value assertions (Law 6). ML-independent; run without `ml` while the
//! embedded weights are mid-retrain.

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

#[test]
fn defeats_combined_homoglyph_and_zero_width_evasion() {
    // Cyrillic-А (U+0410) AND a zero-width space (U+200B) in the same token.
    let creds = scan_credentials("k = \u{0410}KIA\u{200B}QYLPMN5HFIQR7BBB");
    assert!(
        creds.iter().any(|c| c == "AKIAQYLPMN5HFIQR7BBB"),
        "combined homoglyph+zero-width evasion must be defeated; found: {creds:?}"
    );
}

#[test]
fn decodes_a_base64url_encoded_aws_key() {
    // Unpadded base64url of "AKIAQYLPMN5HFIQR7BBB".
    let creds = scan_credentials("t = QUtJQVFZTFBNTjVIRklRUjdCQkI");
    assert!(
        creds.iter().any(|c| c == "AKIAQYLPMN5HFIQR7BBB"),
        "base64url-encoded AWS key must be decoded; found: {creds:?}"
    );
}

#[test]
fn recovers_two_distinct_secrets_on_one_line() {
    let creds = scan_credentials("AKIAQYLPMN5HFIQR7BBB and glpat-ABCDEF1234567890abcd");
    assert!(
        creds.iter().any(|c| c == "AKIAQYLPMN5HFIQR7BBB"),
        "found: {creds:?}"
    );
    assert!(
        creds.iter().any(|c| c == "glpat-ABCDEF1234567890abcd"),
        "found: {creds:?}"
    );
}

#[test]
fn extracts_a_single_quoted_secret() {
    let creds = scan_credentials("key = 'AKIAQYLPMN5HFIQR7BBB'");
    assert!(
        creds.iter().any(|c| c == "AKIAQYLPMN5HFIQR7BBB"),
        "single-quoted secret must be extracted without the quotes; found: {creds:?}"
    );
}

#[test]
fn detects_a_tab_separated_secret() {
    let creds = scan_credentials("key\tAKIAQYLPMN5HFIQR7BBB");
    assert!(
        creds.iter().any(|c| c == "AKIAQYLPMN5HFIQR7BBB"),
        "tab-separated secret must be detected; found: {creds:?}"
    );
}

#[test]
fn reports_each_occurrence_of_a_repeated_secret() {
    // Scan-level results are per-occurrence (dedup is a higher layer): the same
    // key appearing twice yields two findings.
    let creds = scan_credentials("a=AKIAQYLPMN5HFIQR7BBB b=AKIAQYLPMN5HFIQR7BBB");
    let n = creds
        .iter()
        .filter(|c| *c == "AKIAQYLPMN5HFIQR7BBB")
        .count();
    assert_eq!(n, 2, "expected both occurrences; found: {creds:?}");
}
