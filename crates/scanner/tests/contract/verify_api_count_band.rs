//! Contract: verify-enabled detector count is reproducible (README cites ~80 live APIs).

use std::path::PathBuf;

#[test]
fn verify_enabled_detector_count_is_stable() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");

    let mut with_verify = 0usize;
    for entry in std::fs::read_dir(&d).expect("detectors").flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let raw = std::fs::read_to_string(&p).expect("read detector");
        if raw.contains("[detector.verify]") {
            with_verify += 1;
        }
    }

    // Contract floor: at least 80 live-verify handlers documented in README.
    // Upper bound prevents silent inflation without doc update.
    assert!(
        (80..=400).contains(&with_verify),
        "verify-enabled detector count {with_verify} outside contract band [80, 400]; \
         update README and this test together"
    );
}
