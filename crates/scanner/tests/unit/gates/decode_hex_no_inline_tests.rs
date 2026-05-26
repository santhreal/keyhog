//! Gate `decode::hex`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn decode_hex_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/decode/hex.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "decode::hex: move inline tests to crates/scanner/tests/"
    );
}
