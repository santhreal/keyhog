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
