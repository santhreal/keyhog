//! Gate `value_parsers`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn value_parsers_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/value_parsers.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "value_parsers: move inline tests to crates/cli/tests/"
    );
}
