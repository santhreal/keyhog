//! Gate `structured::parsers`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn structured_parsers_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/structured/parsers.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "structured::parsers: move inline tests to crates/scanner/tests/"
    );
}
