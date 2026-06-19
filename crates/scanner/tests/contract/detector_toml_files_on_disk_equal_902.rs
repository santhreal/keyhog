//! Contract: `detectors/*.toml` file count matches the shipped 902 catalog.

use std::path::PathBuf;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

#[test]
fn detector_toml_files_on_disk_equal_902() {
    const EXPECTED: usize = 902;

    let dir = detector_dir();
    let count = std::fs::read_dir(&dir)
        .expect("detectors directory readable")
        .map(|e| e.unwrap_or_else(|err| panic!("read_dir({}) entry failed: {err}", dir.display())))
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("toml"))
        .count();

    assert_eq!(
        count, EXPECTED,
        "detectors/ must contain exactly {EXPECTED} TOML files - README and loader both claim 902"
    );
}
