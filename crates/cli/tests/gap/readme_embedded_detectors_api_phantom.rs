//! KH-GAP-107: README/site API examples call phantom or private detector-loader APIs.
//! The public crate surface exports the fail-closed `load_embedded_detectors_or_fail()`
//! loader and `embedded_detector_count()`.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn readme_api_example_uses_exported_embedded_detector_loader() {
    let lib =
        std::fs::read_to_string(repo_root().join("crates/core/src/lib.rs")).expect("core lib.rs");
    assert!(
        lib.contains("pub(crate) fn embedded_detector_tomls"),
        "sanity: raw embedded TOML accessor must stay private"
    );
    assert!(
        !lib.contains("pub fn embedded_detectors"),
        "embedded_detectors() is not exported; README must not document it"
    );

    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("README.md");
    assert!(
        !readme.contains("embedded_detectors()"),
        "README Library API must not document phantom embedded_detectors()"
    );
    assert!(
        !readme.contains("embedded_detector_tomls()"),
        "README Library API must use load_embedded_detectors_or_fail(), not the private raw TOML accessor"
    );
    assert!(
        readme.contains("load_embedded_detectors_or_fail()"),
        "README Library API must show the public fail-closed embedded detector loader"
    );
}
