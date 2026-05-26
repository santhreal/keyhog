//! Gate `spec::validate`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn spec_validate_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/spec/validate.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "spec::validate: move inline tests to crates/core/tests/"
    );
}
