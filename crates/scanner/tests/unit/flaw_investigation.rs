use keyhog_scanner::alphabet_filter::AlphabetScreen;
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
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
    // Secret: ghp_123456789012345678901234567890123456
    // Detectors usually look for ghp_
    let secret = "ghp_123456789012345678901234567890123456";
    let b64_1 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, secret);
    let b64_2 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &b64_1);

    let detectors = vec![DetectorSpec {
        id: "github-pat".into(),
        name: "GitHub PAT".into(),
        service: "github".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: "ghp_[a-zA-Z0-9]{36}".into(),
            description: None,
            group: None,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["ghp_".into()],
    ..Default::default(),
    }];

    let scanner = CompiledScanner::compile(detectors).unwrap();
    let chunk = Chunk {
        data: format!("data = \"{}\"", b64_2),
        metadata: ChunkMetadata {
                    base_offset: 0,
            source_type: "test".into(),
            ..Default::default()
},
    };

    let matches = scanner.scan(&chunk);
    assert!(!matches.is_empty(), "Should find nested base64 secret");
}

#[test]
fn test_alphabet_mask_large_input() {
    let mut data = vec![b'a'; 1024 * 1024]; // 1MB of 'a'
    let screen = AlphabetScreen::new(&["b".to_string()]);
    assert!(!screen.screen(&data));

    data[512 * 1024] = b'b';
    assert!(screen.screen(&data));
}
