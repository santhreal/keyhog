use std::process::Command;
use vyre_libs::scan::{GpuLiteralSet, MatchEngineCache};

#[test]
fn artifact_writer_emits_manifest_and_vyre_blobs() {
    let detectors = tempfile::TempDir::new().expect("detector tempdir");
    std::fs::write(
        detectors.path().join("kh-artifact-test.toml"),
        r#"
[detector]
id = "kh-artifact-test-token"
name = "Artifact Test Token"
service = "artifact-test"
severity = "low"
keywords = ["KHART"]

[[detector.patterns]]
regex = 'KHART_[A-Za-z0-9]{12}'
description = "Artifact writer smoke token"
"#,
    )
    .expect("write detector");
    let out = tempfile::TempDir::new().expect("artifact output tempdir");

    let output = Command::new(env!("CARGO_BIN_EXE_keyhog-scanner-artifacts"))
        .arg("--detectors")
        .arg(detectors.path())
        .arg("--out-dir")
        .arg(out.path())
        .output()
        .expect("run artifact writer");
    assert!(
        output.status.success(),
        "artifact writer failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let manifest_path = out.path().join("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("manifest should be written"))
            .expect("manifest should be valid json");
    assert_eq!(manifest["format_version"], 1);
    assert_eq!(manifest["detector_count"], 1);
    let artifacts = manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts array");
    assert!(
        artifacts.iter().any(|entry| entry["kind"] == "literal"),
        "manifest must include the main literal artifact: {manifest}"
    );
    assert!(
        artifacts
            .iter()
            .any(|entry| entry["kind"] == "positioned_literal"),
        "manifest must include the positioned literal artifact: {manifest}"
    );

    for entry in artifacts {
        let file_name = entry["file_name"].as_str().expect("artifact file_name");
        let bytes = std::fs::read(out.path().join(file_name)).expect("artifact bytes readable");
        assert!(
            bytes.len() >= GpuLiteralSet::WIRE_MAGIC.len(),
            "artifact {file_name} must include a Vyre literal-set wire header"
        );
        assert_eq!(
            &bytes[..GpuLiteralSet::WIRE_MAGIC.len()],
            &GpuLiteralSet::WIRE_MAGIC,
            "artifact {file_name} must carry Vyre literal-set wire magic"
        );
        GpuLiteralSet::from_bytes(&bytes)
            .unwrap_or_else(|error| panic!("artifact {file_name} must deserialize: {error}"));
    }
}
