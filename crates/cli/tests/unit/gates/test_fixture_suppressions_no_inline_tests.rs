//! Gate `test_fixture_suppressions`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn test_fixture_suppressions_no_inline_tests() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/test_fixture_suppressions.rs"
    );
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "test_fixture_suppressions: move inline tests to crates/cli/tests/"
    );
}
