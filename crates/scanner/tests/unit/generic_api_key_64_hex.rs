use crate::CompiledScanner;
use keyhog_core::Chunk;

#[test]
fn test_generic_api_key_64_hex_cryptographic_positive() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../detectors");
    let specs = keyhog_core::load_detectors(&dir).expect("load detectors");
    let scanner = CompiledScanner::compile(specs).expect("compile scanner");

    let payload =
        r#"{"signing_key": "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a97601b1a7d6e492b"}"#;
    let mut chunk = Chunk::from(payload);
    chunk.metadata.path = Some("config.json".into());
    let matches = scanner.scan_coalesced(&[chunk]).expect("scan chunk");
    assert!(
        !matches.is_empty() && !matches[0].is_empty(),
        "signing_key 64-hex JSON field must match"
    );
    let matched_detector = matches[0][0].detector_id.as_ref();
    assert!(
        matched_detector == "generic-api-key" || matched_detector == "entropy-api-key",
        "expected generic or entropy api key detector match, got {matched_detector}"
    );
    assert_eq!(
        matches[0][0].credential.as_ref(),
        "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a97601b1a7d6e492b"
    );

    let payload_env =
        "signing_key = \"c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a97601b1a7d6e492b\"\n";
    let mut chunk_env = Chunk::from(payload_env);
    chunk_env.metadata.path = Some("config.env".into());
    let matches_env = scanner.scan_coalesced(&[chunk_env]).expect("scan chunk");
    assert!(
        !matches_env.is_empty() && !matches_env[0].is_empty(),
        "signing_key 64-hex assignment must match"
    );
    let matched_detector_env = matches_env[0][0].detector_id.as_ref();
    assert!(
        matched_detector_env == "generic-api-key" || matched_detector_env == "entropy-api-key",
        "expected generic or entropy api key detector match, got {matched_detector_env}"
    );
    assert_eq!(
        matches_env[0][0].credential.as_ref(),
        "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a97601b1a7d6e492b"
    );
}

#[test]
fn test_generic_api_key_64_hex_digest_and_non_crypto_negatives() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../detectors");
    let specs = keyhog_core::load_detectors(&dir).expect("load detectors");
    let scanner = CompiledScanner::compile(specs).expect("compile scanner");

    let negative_payloads = [
        r#"{"sha256": "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a97601b1a7d6e492b"}"#,
        r#"{"checksum": "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a97601b1a7d6e492b"}"#,
        r#"{"commit_hash": "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a97601b1a7d6e492b"}"#,
        r#"{"object_id": "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a97601b1a7d6e492b"}"#,
        r#"{"content_digest": "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a97601b1a7d6e492b"}"#,
        r#"{"api_secret_key_hash": "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a97601b1a7d6e492b"}"#,
        r#"{"api_key": "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a97601b1a7d6e492b"}"#,
    ];

    for payload in negative_payloads {
        let mut chunk = Chunk::from(payload);
        chunk.metadata.path = Some("data.json".into());
        let matches = scanner.scan_coalesced(&[chunk]).expect("scan chunk");
        let generic_matches: Vec<_> = matches
            .into_iter()
            .flatten()
            .filter(|m| m.detector_id.as_ref() == "generic-api-key")
            .collect();
        assert!(
            generic_matches.is_empty(),
            "64-hex SHA-256 digest or non-crypto field payload must not match generic-api-key: {payload}"
        );
    }
}
