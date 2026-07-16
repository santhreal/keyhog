use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;

#[test]
fn custom_detector_identity_reaches_the_exact_scan_finding() {
    const DETECTOR_ID: &str = "identity-propagation-contract";
    const CREDENTIAL: &str = "Q7vN2xK8cP4mR9tW3zH6yL5sD8fJ1bG0";

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("identity-propagation.toml"),
        format!(
            r#"
[detector]
id = "{DETECTOR_ID}"
name = "Identity Propagation Contract"
service = "identity-contract"
severity = "high"
ml = {{ match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }}
keywords = ["identity_contract_"]
min_confidence = 0.0

[[detector.patterns]]
regex = 'identity_contract_([A-Za-z0-9]{{32}})'
group = 1
"#
        ),
    )
    .expect("write custom detector");

    let detectors = keyhog_core::load_detectors(dir.path()).expect("load custom detector");
    let scanner = CompiledScanner::compile(detectors).expect("compile custom detector");
    let chunk = Chunk {
        data: format!("identity_contract_{CREDENTIAL}").into(),
        metadata: ChunkMetadata {
            source_type: "identity-contract".into(),
            path: Some("identity-contract.txt".into()),
            ..Default::default()
        },
    };

    let matching: Vec<_> = scanner
        .scan(&chunk)
        .into_iter()
        .filter(|finding| finding.detector_id.as_ref() == DETECTOR_ID)
        .collect();
    assert_eq!(matching.len(), 1, "exact custom detector must fire once");
    assert_eq!(matching[0].detector_id.as_ref(), DETECTOR_ID);
    assert_eq!(matching[0].credential.as_ref(), CREDENTIAL);
}
