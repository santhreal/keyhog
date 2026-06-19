//! Contract: the loaded corpus size equals the on-disk `detectors/` TOML
//! count — i.e. the loader loads EVERY on-disk detector, none silently
//! dropped. The count is single-sourced from the loader (see
//! `readme_claims::readme_claim_detector_count`); this test pins the
//! internal invariant with no hardcoded number, so adding a detector never
//! requires editing a literal here.

use std::path::PathBuf;

fn detectors_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

#[test]
fn readme_detector_count_matches_disk() {
    let dir = detectors_dir();
    let disk_count = std::fs::read_dir(&dir)
        .expect("detectors/")
        .map(|entry| {
            entry.unwrap_or_else(|e| panic!("read detectors dir entry {}: {e}", dir.display()))
        })
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("toml"))
        .count();

    let loaded = keyhog_core::load_detectors(&dir)
        .expect("detectors/ must load")
        .len();

    assert_eq!(
        disk_count,
        loaded,
        "loader drift: {disk_count} *.toml files on disk in {} but the loader \
         returned {loaded} detectors. A detector TOML is being silently dropped \
         (bad id, duplicate, parse-skip) — every on-disk detector must load.",
        dir.display(),
    );
}
