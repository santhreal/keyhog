//! Gate `error`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn error_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/error.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "error: move inline tests to crates/scanner/tests/"
    );
}
