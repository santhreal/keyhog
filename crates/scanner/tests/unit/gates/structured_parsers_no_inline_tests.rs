//! Gate `structured::parsers`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn structured_parsers_no_inline_tests() {
    for path in parser_source_paths() {
        let src = std::fs::read_to_string(&path).expect("source readable");
        assert!(
            !super::inline_gate::contains_inline_test_module_or_function(&src),
            "structured::parsers: move inline tests to crates/scanner/tests/ in {path}"
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
