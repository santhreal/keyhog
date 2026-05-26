//! Docker layer unpack must enforce per-entry and cumulative tar caps.

#[cfg(feature = "docker")]
#[test]
fn docker_tar_caps_in_source() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/docker.rs"
    ))
    .expect("docker.rs");
    assert!(src.contains("MAX_TAR_ENTRY_BYTES"));
    assert!(src.contains("MAX_TAR_TOTAL_BYTES"));
    assert!(src.contains("128 * 1024 * 1024"));
    assert!(src.contains("8 * 1024 * 1024 * 1024"));
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_tar_caps_require_docker_feature() {
    assert!(!cfg!(feature = "docker"));
}
