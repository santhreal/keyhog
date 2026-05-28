//! KH-GAP-155: Most detectors still lack handwritten near-miss twins.

use std::path::PathBuf;

#[test]
fn r5_handwritten_twin_gap_vs_detector_load() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let loaded = keyhog_core::load_detectors(&d).expect("load").len();
    let adv = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial");
    let handwritten = std::fs::read_dir(&adv)
        .expect("adversarial")
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.starts_with("top50_") && name.contains("_near_miss")
        })
        .count();
    assert!(
        handwritten < loaded,
        "KH-GAP-155: expected handwritten twin gap — {handwritten}/{loaded} covered"
    );
    assert!(
        handwritten >= 50,
        "KH-GAP-155: R5 floor requires >=50 handwritten near-miss twins, got {handwritten}"
    );
}
