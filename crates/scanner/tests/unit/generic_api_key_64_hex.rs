use keyhog_core::Chunk;
use crate::CompiledScanner;

#[test]
fn test_generic_api_key_64_hex_policy() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../detectors");
    let specs = keyhog_core::load_detectors(&dir).expect("load detectors");
    let scanner = CompiledScanner::compile(specs).expect("compile scanner");
    let payload = r#"{"api_secret_key": "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a97601b1a7d6e492b"}"#;
    let mut chunk = Chunk::from(payload);
    chunk.metadata.path = Some("config.json".into());
    let raw_matches = scanner.scan(&chunk).expect("scan chunk");
    println!("raw_matches: {raw_matches:?}");
    let matches = scanner.scan_coalesced(&[chunk]).expect("scan chunk");
    println!("coalesced_matches: {matches:?}");
    assert!(!matches.is_empty() && !matches[0].is_empty(), "api_secret_key 64-hex JSON field must match");
    let generic_match = &matches[0][0];
    assert_eq!(generic_match.detector_id.as_ref(), "generic-api-key");
    assert_eq!(
        generic_match.credential.as_ref(),
        "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a97601b1a7d6e492b"
    );
}

#[test]
fn test_generic_api_secret_key_64_hex_assignment_policy() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../detectors");
    let specs = keyhog_core::load_detectors(&dir).expect("load detectors");
    let target_spec = specs.iter().find(|d| d.id == "generic-api-key").expect("generic-api-key detector spec present");
    println!("GENERIC API KEY KEYWORDS: {:?}", target_spec.keywords);
    println!("GENERIC API KEY CANONICAL HEX: {:?}", target_spec.canonical_hex_key_material);
    let scanner = CompiledScanner::compile(specs).expect("compile scanner");
    let payload = "api_secret_key = \"c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a97601b1a7d6e492b\"\n";
    let mut chunk = Chunk::from(payload);
    chunk.metadata.path = Some("config.env".into());
    let raw = scanner.scan(&chunk).expect("scan");
    println!("RAW: {raw:?}");
    let matches = scanner.scan_coalesced(&[chunk]).expect("scan chunk");
    println!("COALESCED: {matches:?}");
    assert!(!matches.is_empty() && !matches[0].is_empty(), "api_secret_key 64-hex assignment must match");
    let generic_match = &matches[0][0];
    assert_eq!(generic_match.detector_id.as_ref(), "generic-api-key");
    assert_eq!(
        generic_match.credential.as_ref(),
        "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a97601b1a7d6e492b"
    );
}
