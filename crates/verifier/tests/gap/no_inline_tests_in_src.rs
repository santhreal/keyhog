//! KH-GAP-004 (verifier slice): src/ must not host #[cfg(test)] modules;
//! all tests live under tests/.

fn walk_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_inline_tests_in_verifier_src() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk_rs_files(&src, &mut files);

    let violations: Vec<_> = files
        .into_iter()
        .filter(|path| {
            let content = std::fs::read_to_string(path).expect("read src file");
            content.contains("#[cfg(test)]")
        })
        .collect();

    assert!(
        violations.is_empty(),
        "verifier src must not contain #[cfg(test)] modules; move to tests/: {:?}",
        violations
    );
}
