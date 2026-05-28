//! KH-GAP-154: Data-driven per-detector near-miss runner present.

use std::path::PathBuf;

#[test]
fn r5_per_detector_near_miss_runner_present() {
    let runner = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/per_detector_hostile_near_miss_runner.rs");
    assert!(
        runner.is_file(),
        "KH-GAP-154: missing per_detector_hostile_near_miss_runner.rs"
    );
}
