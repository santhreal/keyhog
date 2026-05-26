//! Gate `path_validation`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn path_validation_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/path_validation.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "path_validation: move inline tests to crates/cli/tests/"
    );
}
