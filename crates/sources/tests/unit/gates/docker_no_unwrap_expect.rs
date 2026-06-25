//! Gate `docker`: no .unwrap( / .expect( in production source lines.

#[test]
fn docker_no_unwrap_expect() {
    let mut offenders: Vec<(String, usize, String)> = Vec::new();
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
        for (i, line) in src.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("//") || t.contains("#[cfg(test)]") {
                continue;
            }
            if t.contains(".unwrap(") || t.contains(".expect(") {
                offenders.push((rel_path.into(), i + 1, line.into()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "docker: unwrap/expect in production source at {:?}",
        offenders.iter().take(5).collect::<Vec<_>>()
    );
}
