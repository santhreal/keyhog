//! KH-GAP-004: orchestrator.rs still hosts inline tests.

#[test]
fn inline_test_offenders_orchestrator() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator.rs");
    let content = std::fs::read_to_string(path).expect("read");
    let has_inline = content.lines().any(|l| l.trim().starts_with("#[cfg(test)]"));
    assert!(!has_inline, "orchestrator.rs must migrate inline tests to tests/unit/");
}
