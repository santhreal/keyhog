//! Gate `test_fixture_suppressions`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn test_fixture_suppressions_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/test_fixture_suppressions.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "test_fixture_suppressions: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "test_fixture_suppressions: todo!/unimplemented! forbidden in non-test source"
    );
}
