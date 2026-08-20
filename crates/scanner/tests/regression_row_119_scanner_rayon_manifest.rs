//! WHY: Closes the defect class where `keyhog-scanner` declared `rayon` in `[dependencies]`
//! despite the crate having zero internal multi-threading and relying exclusively on caller-driven
//! concurrency (Row 119).
//!
//! What this does NOT catch: dynamic library dependencies linked at runtime outside Cargo manifests.

#[test]
fn row_119_scanner_manifest_declares_rayon_only_in_dev_dependencies() {
    let manifest_str = include_str!("../Cargo.toml");
    let manifest: toml::Table =
        toml::from_str(manifest_str).expect("crates/scanner/Cargo.toml must parse as valid TOML");

    if let Some(deps) = manifest.get("dependencies").and_then(|d| d.as_table()) {
        assert!(
            !deps.contains_key("rayon"),
            "keyhog-scanner [dependencies] must not contain 'rayon' (caller provides concurrency)"
        );
    }

    let dev_deps = manifest
        .get("dev-dependencies")
        .and_then(|d| d.as_table())
        .expect("crates/scanner/Cargo.toml must have [dev-dependencies]");

    assert!(
        dev_deps.contains_key("rayon"),
        "keyhog-scanner [dev-dependencies] must contain 'rayon' for integration benchmarks and tests"
    );
}
