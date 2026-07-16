use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::testing::AlphabetScreen;
use keyhog_scanner::CompiledScanner;

#[test]
fn test_alphabet_mask_scalar_vs_simd_consistency() {
    let data = b"The quick brown fox jumps over the lazy dog. 1234567890!@#$%^&*()_+";
    let screen = AlphabetScreen::new(&["quick".to_string(), "123".to_string()]);

    // This should always pass if implementation is correct (even if scalar)
    assert!(screen.screen(data));

    let no_match = b"zzzzzzzzzzzzzzzzzzzz";
    assert!(!screen.screen(no_match));
}

#[test]
fn test_nested_base64_decoding_gating() {
    // Secret: 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 (checksum-VALID GitHub
    // classic PAT - trailing 6 chars are the base62 CRC32 of the leading 30; a
    // fabricated `ghp_` is now correctly dropped before scoring, so the nested-
    // base64 decode path must surface a token that actually validates).
    let secret = concat!("gh", "p_1234567890123456789012345678902PDSiF");
    let b64_1 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, secret);
    let b64_2 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &b64_1);

    let detectors = vec![DetectorSpec {
        tests: Vec::new(),
        id: "github-pat".into(),
        name: "GitHub PAT".into(),
        service: "github".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: "ghp_[a-zA-Z0-9]{36}".into(),
            description: None,
            group: None,
            client_safe: false,
            weak_anchor: false,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["ghp_".into()],
        min_confidence: None,
        ..Default::default()
    }];

    let scanner = CompiledScanner::compile(detectors).unwrap();
    let chunk = Chunk {
        data: format!("data = \"{}\"", b64_2).into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "test".into(),
            ..Default::default()
        },
    };

    let matches = scanner.scan(&chunk);
    let hit =
        matches
            .iter()
            .find(|m| m.detector_id.as_ref() == "github-pat" && m.credential.as_ref() == secret)
            .unwrap_or_else(|| {
                panic!(
                "nested-base64 decode must surface the GitHub PAT verbatim (got {} matches: {:?})",
                matches.len(),
                matches.iter().map(|m| m.detector_id.as_ref()).collect::<Vec<_>>()
            )
            });
    assert_eq!(hit.detector_id.as_ref(), "github-pat");
    assert_eq!(hit.credential.as_ref(), secret);
}

#[test]
fn test_alphabet_mask_large_input() {
    let mut data = vec![b'a'; 1024 * 1024]; // 1MB of 'a'
    let screen = AlphabetScreen::new(&["b".to_string()]);
    assert!(!screen.screen(&data));

    data[512 * 1024] = b'b';
    assert!(screen.screen(&data));
}
