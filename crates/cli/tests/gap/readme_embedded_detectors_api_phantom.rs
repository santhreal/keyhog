//! KH-GAP-107: README/site API examples call `keyhog_core::embedded_detectors()`
//! but the public crate surface exports `embedded_detector_tomls()` / `embedded_detector_count()`.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn readme_api_example_uses_exported_embedded_detector_loader() {
    let lib = std::fs::read_to_string(
        repo_root().join("crates/core/src/lib.rs"),
    )
    .expect("core lib.rs");
    assert!(
        lib.contains("pub fn embedded_detector_tomls"),
        "sanity: embedded_detector_tomls must exist"
    );
    assert!(
        !lib.contains("pub fn embedded_detectors"),
        "embedded_detectors() is not exported; README must not document it"
    );

    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("README.md");
    assert!(
        !readme.contains("embedded_detectors()"),
        "README Library API must use embedded_detector_tomls()/load_detectors, not phantom embedded_detectors()"
    );
}
