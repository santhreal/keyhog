//! KH-GAP-128: Bulk contract multipliers scale to 894 detectors but lack
//! per-detector hostile near-miss / positive twin oracles (only top-10 covered).

use std::path::PathBuf;

#[test]
fn per_detector_hostile_near_miss_harness_exists() {
    let tests_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let runner = tests_dir.join("per_detector_hostile_near_miss_runner.rs");
    assert!(
        runner.is_file(),
        "KH-GAP-128: missing data-driven per-detector hostile near-miss runner. \
         only top-10 hand-written near_miss_must_not_fire twins exist"
    );
}

#[test]
fn near_miss_coverage_floor_meets_loaded_detector_count() {
    let detectors = keyhog_core::load_detectors(&{
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.pop();
        d.pop();
        d.push("detectors");
        d
    })
    .expect("load detectors");

    let contracts_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/contracts");
    let mut covered = 0usize;
    for entry in std::fs::read_dir(contracts_dir).expect("contracts dir") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read contract");
        let has_negative = text.contains("[[negative]]");
        let has_positive = text.contains("[[positive]]");
        if has_negative || has_positive {
            covered += 1;
        }
    }

    assert!(
        covered >= detectors.len(),
        "KH-GAP-128: near-miss contract coverage {covered}/{}. \
         per_detector_hostile_near_miss_runner must cover every loaded detector",
        detectors.len()
    );
}
