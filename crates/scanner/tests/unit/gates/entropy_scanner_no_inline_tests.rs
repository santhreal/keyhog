//! Gate `entropy::scanner`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn entropy_scanner_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/entropy/scanner.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "entropy::scanner: move inline tests to crates/scanner/tests/"
    );
}
