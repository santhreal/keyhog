use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;

#[test]
fn custom_regex_detector_enforces_its_toml_minimum_length() {
    const SHORT: &str = "Q7vN2xK8cP4mR9tW";
    const EXACT: &str = "Q7vN2xK8cP4mR9tW3zH6yL5sD8fJ1bG0";

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("min-length.toml"),
        r#"
[detector]
id = "detector-min-length-contract"
name = "Detector Minimum Length Contract"
service = "length-contract"
severity = "high"
keywords = ["length_contract_"]
min_confidence = 0.0
min_len = 32

[[detector.patterns]]
regex = 'length_contract_([A-Za-z0-9]{16,32})'
group = 1
"#,
    )
    .expect("write custom detector");

    let detectors = keyhog_core::load_detectors(dir.path()).expect("load custom detector");
    let scanner = CompiledScanner::compile(detectors).expect("compile custom detector");
    let chunk = Chunk {
        data: format!("length_contract_{SHORT}\nlength_contract_{EXACT}").into(),
        metadata: ChunkMetadata {
            source_type: "length-contract".into(),
            path: Some("length-contract.txt".into()),
            ..Default::default()
        },
    };

    let credentials: Vec<_> = scanner
        .scan(&chunk)
        .into_iter()
        .filter(|finding| finding.detector_id.as_ref() == "detector-min-length-contract")
        .map(|finding| finding.credential.to_string())
        .collect();
    assert_eq!(credentials, [EXACT]);
}
