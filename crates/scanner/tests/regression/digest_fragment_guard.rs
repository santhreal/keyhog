use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;

fn hex32_detector() -> DetectorSpec {
    DetectorSpec {
        id: "hex32-api-key".into(),
        name: "Hex32 API Key".into(),
        service: "hex32".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: r#"HEX32_API_KEY[=:\s"']+([a-f0-9]{32})"#.into(),
            description: Some("test-only 32-hex token".into()),
            group: Some(1),
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["HEX32_API_KEY".into()],
        min_confidence: None,
        ..Default::default()
    }
}

fn scan_text(text: &str) -> Vec<keyhog_core::RawMatch> {
    let scanner = CompiledScanner::compile(vec![hex32_detector()]).expect("compile detector");
    scanner.scan(&Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("digest.env".into()),
            ..Default::default()
        },
    })
}

#[test]
fn leading_32_hex_slice_of_sha256_is_suppressed() {
    let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let matches = scan_text(&format!("HEX32_API_KEY={digest}\n"));

    assert!(
        matches.is_empty(),
        "a 32-hex detector must not report the leading slice of a 64-hex digest: {matches:?}"
    );
}

#[test]
fn delimiter_bounded_32_hex_token_still_fires() {
    let token = "0123456789abcdef0123456789abcdef";
    let matches = scan_text(&format!("HEX32_API_KEY={token}\n"));

    assert!(
        !matches.is_empty(),
        "a delimiter-bounded 32-hex token must still report: {matches:?}"
    );
    assert!(
        matches.iter().all(|m| {
            m.detector_id.as_ref() == "hex32-api-key" && m.credential.as_ref() == token
        }),
        "every raw hit must preserve the planted detector and credential: {matches:?}"
    );
}
