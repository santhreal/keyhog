use super::super::setup_default_scan_runtime_for_test;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::ScanBackend;
use std::collections::BTreeSet;
use std::path::Path;

const EMBEDDED_AWS_KEY: &str = "AKIAQYLPMN5HFIQR7XYA";
const CUSTOM_TOKEN: &str = "CUSTOM_SHARED_RUNTIME_ABCD1234";
const CUSTOM_DETECTOR_ID: &str = "shared-runtime-custom";

fn write_custom_detector(root: &Path) {
    let detector_dir = root.join("custom-detectors");
    std::fs::create_dir_all(&detector_dir).expect("create custom detector directory");
    let detector = keyhog_core::testing::detector_toml_with_fixture_confidence(
        r#"[detector]
id = "shared-runtime-custom"
name = "Shared runtime custom fixture"
service = "fixture"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
keywords = ["CUSTOM_SHARED_RUNTIME_"]

[[detector.patterns]]
regex = "CUSTOM_SHARED_RUNTIME_[A-Z0-9]{8}"
"#,
    );
    std::fs::write(detector_dir.join("custom.toml"), detector)
        .expect("write custom detector");
}

fn runtime_findings(mode: &str) -> BTreeSet<String> {
    let root = tempfile::tempdir().expect("tempdir");
    write_custom_detector(root.path());
    std::fs::write(
        root.path().join(".keyhog.toml"),
        format!(
            "detectors = \"custom-detectors\"\ndetectors_mode = \"{mode}\"\nno_decode = true\nno_entropy = true\n"
        ),
    )
    .expect("write config");

    let runtime = setup_default_scan_runtime_for_test(
        Path::new("detectors"),
        false,
        None,
        Some(rayon::current_num_threads()),
        Some(ScanBackend::CpuFallback),
        "keyhog watch",
        false,
        Some(root.path()),
    )
    .expect("construct shared watch/scan-system runtime");
    let chunk = Chunk {
        data: format!(
            "AWS_ACCESS_KEY_ID={EMBEDDED_AWS_KEY}\ncustom_token={CUSTOM_TOKEN}\n"
        )
        .into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some(root.path().join("planted.txt").display().to_string().into()),
            ..ChunkMetadata::default()
        },
    };

    runtime
        .scan_chunk(&chunk)
        .expect("scan planted embedded and custom credentials")
        .into_iter()
        .map(|finding| finding.detector_id.to_string())
        .collect()
}

/// Regression: the production runtime shared by `watch` and `scan-system`
/// previously called the legacy replacement-only loader after resolving
/// `.keyhog.toml`, so `detectors_mode = "overlay"` silently discarded every
/// embedded rule. Overlay must retain both corpora, while the replace twin must
/// still exclude embedded rules rather than introducing an implicit fallback.
#[test]
fn shared_runtime_respects_configured_overlay_and_replace_corpora() {
    let overlay = runtime_findings("overlay");
    assert!(
        overlay.contains("aws-access-key"),
        "overlay must retain the embedded AWS detector: {overlay:?}"
    );
    assert!(
        overlay.contains(CUSTOM_DETECTOR_ID),
        "overlay must retain the configured custom detector: {overlay:?}"
    );

    let replace = runtime_findings("replace");
    assert!(
        replace.contains(CUSTOM_DETECTOR_ID),
        "replace must load the configured custom detector: {replace:?}"
    );
    assert!(
        !replace.contains("aws-access-key"),
        "replace must exclude embedded detectors: {replace:?}"
    );
}
