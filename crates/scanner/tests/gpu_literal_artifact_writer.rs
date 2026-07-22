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
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
match_confidence = { literal_prefix_weight = 0.35, context_anchor_weight = 0.20, entropy_weight = 0.20, high_entropy_partial_weight = 0.12, moderate_entropy_threshold = 3.0, moderate_entropy_weight = 0.05, low_entropy_penalty_floor = 2.0, low_entropy_min_match_length = 10, low_entropy_penalty_multiplier = 0.60, keyword_nearby_weight = 0.10, sensitive_file_weight = 0.10, companion_weight = 0.05, very_high_entropy_margin = 1.3, named_anchor_floor = 0.55, assignment_context_multiplier = 1.0, string_literal_context_multiplier = 0.9, unknown_context_multiplier = 0.8, documentation_context_multiplier = 0.3, comment_context_multiplier = 0.4, test_context_multiplier = 0.3, encrypted_context_multiplier = 0.05, soft_context_suppression_threshold = 0.5, encrypted_context_suppression_threshold = 0.8, length_lift_divisor = 100.0, length_lift_max = 0.15, low_promise_confidence = 0.10, high_promise_confidence = 0.30, high_entropy_min_length = 16 }
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
            .all(|entry| entry["kind"] != "positioned_literal"),
        "manifest must not emit the superseded second matcher artifact: {manifest}"
    );

    for entry in artifacts {
        let file_name = entry["file_name"].as_str().expect("artifact file_name");
        let bytes = std::fs::read(out.path().join(file_name)).expect("artifact bytes readable");
        assert!(
            bytes.len() >= GpuLiteralSet::WIRE_MAGIC.len(),
            "artifact {file_name} must include a VYRE literal-set wire header"
        );
        assert_eq!(
            &bytes[..GpuLiteralSet::WIRE_MAGIC.len()],
            &GpuLiteralSet::WIRE_MAGIC,
            "artifact {file_name} must carry VYRE literal-set wire magic"
        );
        GpuLiteralSet::from_bytes(&bytes)
            .unwrap_or_else(|error| panic!("artifact {file_name} must deserialize: {error}"));
    }
}
