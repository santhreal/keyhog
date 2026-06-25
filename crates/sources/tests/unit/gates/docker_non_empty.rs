//! Gate `docker`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn docker_non_empty() {
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
            src.trim().len() >= 20,
            "docker: expected substantive source in {rel_path}, got {} trimmed bytes",
            src.trim().len()
        );
        let prod = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
            "docker: todo!/unimplemented! forbidden in non-test source {rel_path}"
        );
    }
}
