//! Contract: README claims 891 detectors — tree must match exactly.

use std::path::PathBuf;

#[test]
fn readme_detector_count_matches_disk() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let count = std::fs::read_dir(&d)
        .expect("detectors/")
        .flatten()
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("toml"))
        .count();
    assert_eq!(
        count, 891,
        "README contract: 891 detector TOMLs on disk, found {count}"
    );
}
