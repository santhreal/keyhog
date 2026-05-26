//! KH-GAP-004: orchestrator module tree must not host inline tests.

#[test]
fn inline_test_offenders_orchestrator() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator");
    for entry in std::fs::read_dir(dir).expect("read orchestrator dir") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|e| e == "rs") {
            let content = std::fs::read_to_string(&path).expect("read");
            let has_inline = content.lines().any(|l| l.trim().starts_with("#[cfg(test)]"));
            assert!(!has_inline, "{} must migrate inline tests to tests/unit/", path.display());
        }
    }
}
