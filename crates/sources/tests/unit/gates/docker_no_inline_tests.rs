//! Gate `docker`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn docker_no_inline_tests() {
    for rel_path in [
        "src/docker.rs",
        "src/docker/archive.rs",
        "src/docker/file_read.rs",
        "src/docker/layer.rs",
        "src/docker/metadata.rs",
        "src/docker/oci.rs",
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel_path);
        let src = std::fs::read_to_string(&path).expect("source readable");
        assert!(
            !src.contains("#[cfg(test)]"),
            "docker: move inline tests from {rel_path} to crates/sources/tests/"
        );
    }
}
