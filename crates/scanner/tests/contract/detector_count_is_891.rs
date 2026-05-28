//! Contract: shipped detector count is exactly 891.

use std::path::PathBuf;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

#[test]
fn detector_count_is_891() {
    const EXPECTED: usize = 891;

    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("detectors directory must load");
    assert_eq!(
        detectors.len(),
        EXPECTED,
        "loaded detector count must match contract - update EXPECTED only after \
         intentional catalog change"
    );
}
