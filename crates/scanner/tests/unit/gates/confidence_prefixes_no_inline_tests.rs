//! Gate `confidence::prefixes`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn confidence_prefixes_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/confidence/prefixes.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "confidence::prefixes: move inline tests to crates/scanner/tests/"
    );
}
