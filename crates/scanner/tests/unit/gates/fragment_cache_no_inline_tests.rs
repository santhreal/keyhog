//! Gate `fragment_cache`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn fragment_cache_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/fragment_cache.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !super::inline_gate::contains_inline_test_module_or_function(&src),
        "fragment_cache: move inline tests to crates/scanner/tests/"
    );
}
