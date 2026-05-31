//! Contract: `detectors/*.toml` file count matches the shipped 894 catalog.

use std::path::PathBuf;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

#[test]
fn detector_toml_files_on_disk_equal_891() {
    const EXPECTED: usize = 894;

    let count = std::fs::read_dir(detector_dir())
        .expect("detectors directory readable")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("toml"))
        .count();

    assert_eq!(
        count, EXPECTED,
        "detectors/ must contain exactly {EXPECTED} TOML files - README and loader both claim 894"
    );
}
