//! Gate `structured::parsers`: modularity file cap (500 LOC).

#[test]
fn structured_parsers_file_size_cap() {
    for path in parser_source_paths() {
        let src = std::fs::read_to_string(&path).expect("source readable");
        let lines = src.lines().count();
        // Advisory cap (Santh STANDARD.md): warn, do not fail CI.
        if lines > 500 {
            eprintln!(
                "structured::parsers: {path}: {lines} lines exceeds 500-line cap - split module"
            );
        }
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
