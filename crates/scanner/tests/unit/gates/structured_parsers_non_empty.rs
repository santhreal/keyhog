//! Gate `structured::parsers`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn structured_parsers_non_empty() {
    for path in parser_source_paths() {
        let src = std::fs::read_to_string(&path).expect("source readable");
        assert!(
            src.trim().len() >= 20,
            "structured::parsers: {path}: expected substantive source, got {} trimmed bytes",
            src.trim().len()
        );
        let prod = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
            "structured::parsers: {path}: todo!/unimplemented! forbidden in non-test source"
        );
    }
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
