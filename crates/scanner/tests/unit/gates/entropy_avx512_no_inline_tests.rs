//! Gate `entropy_avx512`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn entropy_avx512_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/entropy/avx512.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !super::inline_gate::contains_inline_test_module_or_function(&src),
        "entropy_avx512: move inline tests to crates/scanner/tests/"
    );
}
