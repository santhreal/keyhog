//! Gate `filesystem`: no .unwrap( / .expect( in production source lines.

#[test]
fn filesystem_no_unwrap_expect() {
    let mut offenders: Vec<(String, usize, String)> = Vec::new();
    for rel in [
        "src/filesystem.rs",
        "src/filesystem/extract.rs",
        "src/filesystem/filter.rs",
    ] {
        let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
        let src = std::fs::read_to_string(&path).expect("source readable");
        for (i, line) in src.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("//") || t.contains("#[cfg(test)]") {
                continue;
            }
            if t.contains(".unwrap(") || t.contains(".expect(") {
                offenders.push((rel.to_string(), i + 1, line.to_string()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "filesystem: unwrap/expect in production source at {:?}",
        offenders.iter().take(5).collect::<Vec<_>>()
    );
}
