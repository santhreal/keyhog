//! Gate `decode::base64`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn decode_base64_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/decode/base64.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !super::inline_gate::contains_inline_test_module_or_function(&src),
        "decode::base64: move inline tests to crates/scanner/tests/"
    );
}
