#[test]
fn build_script_cannot_emit_empty_embedded_detector_corpus() {
    let build_rs = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/build.rs"));

    assert!(
        !build_rs.contains("embedded detectors will be empty"),
        "core build.rs must fail the build when detectors/ is missing, not warn and emit an empty corpus"
    );
    assert!(
        !build_rs.contains("write_embedded_detectors(&output_path, &[])?"),
        "core build.rs must not generate an empty embedded detector table"
    );
    assert!(
        !build_rs.contains("detector_set_digest(&[])"),
        "core build.rs must not stamp a valid-looking digest for an empty detector set"
    );
    assert!(
        build_rs.contains("io::ErrorKind::NotFound")
            && build_rs.contains("detectors/ directory not found; searched:")
            && build_rs.contains("package the detector TOMLs with keyhog-core"),
        "missing detector corpus must be a build error with an actionable fix"
    );
}

#[test]
fn packaged_core_detector_path_is_nonempty() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let package_detector_dir = manifest_dir.join("detectors");
    let mut detector_count = 0usize;
    for entry in std::fs::read_dir(&package_detector_dir).unwrap_or_else(|error| {
        panic!(
            "core package detector directory {} must be readable: {error}",
            package_detector_dir.display()
        )
    }) {
        let entry = entry.unwrap_or_else(|error| {
            panic!(
                "core package detector directory {} entries must be readable: {error}",
                package_detector_dir.display()
            )
        });
        if entry.path().extension().is_some_and(|ext| ext == "toml") {
            detector_count += 1;
        }
    }

    assert!(
        detector_count > 0,
        "crates/core/detectors must contain detector TOMLs so cargo package/cargo install builds embed a real corpus"
    );
}
