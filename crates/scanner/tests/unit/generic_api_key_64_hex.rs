use keyhog_core::Chunk;
use crate::testing::named_detector_fixture_defaults;
use crate::CompiledScanner;

#[test]
fn test_generic_api_key_64_hex_policy() {
    let spec = keyhog_core::DetectorSpec {
        id: "generic-api-key".into(),
        name: "Generic API Key".into(),
        service: "generic".into(),
        severity: keyhog_core::Severity::Medium,
        patterns: vec![keyhog_core::PatternSpec {
            regex: r#"(?i)"api[_\-\s]*key"\s*:\s*"([a-zA-Z0-9/+=_.!@#$%^&*-]{12,80})""#.into(),
            group: Some(1),
            ..Default::default()
        }],
        ..named_detector_fixture_defaults()
    };

    let scanner = CompiledScanner::compile(vec![spec]).expect("compile generic api key spec");
    let payload = r#"{"api_key": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}"#;
    let chunk = Chunk::from(payload);
    let matches = scanner.scan_coalesced(&[chunk]).expect("scan chunk");

    assert!(!matches.is_empty() && !matches[0].is_empty(), "explicit API key 64-hex JSON pattern must surface");
    assert_eq!(
        matches[0][0].credential.as_ref(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}
