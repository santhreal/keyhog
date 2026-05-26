//! KH-GAP-004: value_parsers.rs still hosts inline tests.

#[test]
fn inline_test_offenders_value_parsers() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/value_parsers.rs");
    let content = std::fs::read_to_string(path).expect("read");
    let has_inline = content.lines().any(|l| l.trim().starts_with("#[cfg(test)]"));
    assert!(!has_inline, "value_parsers.rs must migrate inline tests to tests/unit/");
}
