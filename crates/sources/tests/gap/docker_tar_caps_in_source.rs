//! Docker layer unpack must enforce per-entry and cumulative tar caps.

#[cfg(feature = "docker")]
#[test]
fn docker_tar_caps_in_source() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/docker.rs"))
        .expect("docker.rs");
    assert!(
        !src.contains("MAX_TAR_ENTRY_BYTES") && !src.contains("MAX_TAR_TOTAL_BYTES"),
        "Docker tar caps must be owned by SourceLimits"
    );
    assert!(
        src.contains("docker_tar_entry_bytes")
            && src.contains("docker_image_config_bytes")
            && src.contains("docker_tar_total_bytes"),
        "Docker source must use resolved SourceLimits for all archive/config caps"
    );
    let limits = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/limits.rs"))
        .expect("limits.rs");
    assert!(limits.contains("docker_tar_entry_bytes: 128 * 1024 * 1024"));
    assert!(limits.contains("docker_tar_total_bytes: 8 * 1024 * 1024 * 1024"));
}

#[cfg(feature = "docker")]
#[test]
fn docker_layer_validation_and_extraction_share_one_open_descriptor() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/docker.rs"))
        .expect("docker.rs");
    let unpack_layer = src
        .split("fn unpack_layer_archive(")
        .nth(1)
        .expect("unpack_layer_archive must exist")
        .split("fn validate_tar_reader")
        .next()
        .expect("unpack_layer_archive section must be bounded");

    assert_eq!(
        unpack_layer.matches("File::open(archive_path)").count(),
        1,
        "Docker layer validation and extraction must share one opened file descriptor"
    );
    assert!(
        unpack_layer.contains("layer_archive_encoding(&mut file)")
            && unpack_layer.contains("file.rewind().map_err(SourceError::Io)?"),
        "Docker layer unpack must sniff, validate, rewind, and extract through the same descriptor"
    );
    for stale_name in ["validation_file", "extract_file"] {
        assert!(
            !unpack_layer.contains(stale_name),
            "Docker layer unpack must not keep the old two-open {stale_name} path"
        );
    }
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_tar_caps_require_docker_feature() {
    assert!(!cfg!(feature = "docker"));
}
