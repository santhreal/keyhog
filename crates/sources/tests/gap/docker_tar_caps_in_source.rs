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

#[cfg(not(feature = "docker"))]
#[test]
fn docker_tar_caps_require_docker_feature() {
    assert!(!cfg!(feature = "docker"));
}
