//! Gate `structured::parsers`: no .unwrap( / .expect( in production source lines.

#[test]
fn structured_parsers_no_unwrap_expect() {
    let mut offenders: Vec<(String, usize, String)> = Vec::new();
    for path in parser_source_paths() {
        let src = std::fs::read_to_string(&path).expect("source readable");
        for (i, line) in src.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("//") || t.contains("#[cfg(test)]") {
                continue;
            }
            if t.contains(".unwrap(") || t.contains(".expect(") {
                offenders.push((path.clone(), i + 1, line.to_string()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "structured::parsers: unwrap/expect in production source at {:?}",
        offenders.iter().take(5).collect::<Vec<_>>()
    );
}

fn parser_source_paths() -> Vec<String> {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut paths = vec![format!("{root}/src/structured/parsers.rs")];
    let dir = format!("{root}/src/structured/parsers");
    for entry in std::fs::read_dir(&dir).expect("parser module dir readable") {
        let entry = entry.expect("parser module entry readable");
        if entry.path().extension().is_some_and(|ext| ext == "rs") {
            paths.push(entry.path().display().to_string());
        }
    }
    paths
}
