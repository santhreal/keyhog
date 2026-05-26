//! Gate `test_fixture_suppressions`: modularity file cap (500 LOC).

#[test]
fn test_fixture_suppressions_file_size_cap() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/test_fixture_suppressions.rs"
    );
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "test_fixture_suppressions: {lines} lines exceeds 500-line cap — split module"
    );
}
