//! KH-GAP-004: detectors.rs still hosts inline tests.

#[test]
fn inline_test_offenders_detectors_subcommand() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/subcommands/detectors.rs");
    let content = std::fs::read_to_string(path).expect("read");
    let has_inline = content
        .lines()
        .any(|l| l.trim().starts_with("#[cfg(test)]"));
    assert!(
        !has_inline,
        "detectors.rs must migrate inline tests to tests/unit/"
    );
}
