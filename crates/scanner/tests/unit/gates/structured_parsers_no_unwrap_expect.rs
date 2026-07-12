//! Gate `structured::parsers`: no .unwrap( / .expect( in production source lines.

use super::support::unwrap_expect_offenders;

#[test]
fn structured_parsers_no_unwrap_expect() {
    let mut offenders: Vec<(String, usize, String)> = Vec::new();
    for path in parser_source_paths() {
        let src = std::fs::read_to_string(&path).expect("source readable");
        // Shared single-line scan (this gate spans the whole parsers/ dir, so it
        // owns each offender's path); the block-aware GPU variant stays separate.
        for (line_no, line) in unwrap_expect_offenders(&src) {
            offenders.push((path.clone(), line_no, line.to_string()));
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
