//! Gate: shipped ML weights carry honest, build-validated provenance.

use keyhog_scanner::ml_scorer::{model_card_json, model_card_summary, model_version};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(root: &Path, rel: &str) -> String {
    let path = root.join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn fnv1a64(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

#[test]
fn ml_model_card_matches_embedded_weights_and_version_surface() {
    let root = repo_root();
    let card_src = read(&root, "crates/scanner/src/model_card.json");
    let card: serde_json::Value =
        serde_json::from_str(&card_src).expect("model_card.json must be valid JSON");
    let weights = std::fs::read(root.join("crates/scanner/src/weights.bin"))
        .expect("embedded weights.bin must be readable");
    let digest = fnv1a64(&weights);
    let expected_version = format!("moe-v1-{digest}");

    assert_eq!(
        card.pointer("/model_version").and_then(|v| v.as_str()),
        Some(expected_version.as_str()),
        "model_card.json must identify the exact weights.bin hash"
    );
    assert_eq!(
        card.pointer("/weights_fnv1a64").and_then(|v| v.as_str()),
        Some(digest.as_str()),
        "model_card.json weights_fnv1a64 must match weights.bin"
    );
    assert_eq!(
        model_version(),
        expected_version.as_str(),
        "scanner model_version() must be generated from the same weights hash"
    );
    assert_eq!(
        model_card_json(),
        card_src,
        "scanner must embed the checked-in model card JSON byte-for-byte"
    );
    assert!(
        model_card_summary().contains("synthetic F1")
            && model_card_summary().contains("real recall@0.40"),
        "version output summary must include the model-card quality gates: {}",
        model_card_summary()
    );

    for pointer in [
        "/schema_version",
        "/recorded_date",
        "/trainer",
        "/feature_source",
        "/metrics/synthetic_heldout/f1",
        "/metrics/synthetic_heldout/precision",
        "/metrics/synthetic_heldout/recall",
        "/metrics/real_heldout/recall_at_0_40_floor",
    ] {
        assert!(
            card.pointer(pointer).is_some(),
            "model_card.json missing required provenance field {pointer}"
        );
    }
}

#[test]
fn trainer_and_build_script_keep_model_card_fail_closed() {
    let root = repo_root();
    let train = read(&root, "ml/train_classifier.py");
    assert!(
        train.contains("def write_model_card")
            && train.contains("--model-card")
            && train.contains("weights_fnv1a64")
            && train.contains("REFUSING to write: --write requires --real-corpus")
            && train.contains("recall_at_0_40_floor before weights.bin is touched")
            && train.contains("def per_class_eval")
            && train.contains("per_class_gate_error")
            && train.contains("--min-real-class-recall")
            && train.contains("per_detector")
            && train.contains("six_scanner_differential_comparison")
            && train.contains("--differential-results")
            && train.contains("six_scanner_differential"),
        "train_classifier.py must update model_card.json with weights hash plus aggregate/per-class/per-detector real held-out recall and six-scanner class differential before shipped writes"
    );

    let report = read(&root, "benchmarks/bench/report.py");
    assert!(
        report.contains("FULL_DIFFERENTIAL_SCANNERS")
            && report.contains("def class_recall_differential")
            && report.contains("required_scanners"),
        "bench report must own the structured six-scanner class differential consumed by the trainer"
    );

    let build = read(&root, "crates/scanner/build.rs");
    assert!(
        build.contains("src/model_card.json")
            && build.contains("model_card.json model_version mismatch")
            && build.contains("model_card.json weights_fnv1a64 mismatch")
            && build.contains("MODEL_CARD_SUMMARY"),
        "build.rs must validate model_card.json against weights.bin and generate the runtime provenance constants"
    );
}
