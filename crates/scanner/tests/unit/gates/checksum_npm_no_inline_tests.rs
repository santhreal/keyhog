//! Gate `checksum::npm`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn checksum_npm_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/checksum/npm.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "checksum::npm: move inline tests to crates/scanner/tests/"
    );
}
