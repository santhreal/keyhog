//! Gate `engine::phase2`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn engine_phase2_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/phase2.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !super::inline_gate::contains_inline_test_module_or_function(&src),
        "engine::phase2: move inline tests to crates/scanner/tests/"
    );
}
