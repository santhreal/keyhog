//! Gate `decode::caesar`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn decode_caesar_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/decode/caesar.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "decode::caesar: move inline tests to crates/scanner/tests/"
    );
}
