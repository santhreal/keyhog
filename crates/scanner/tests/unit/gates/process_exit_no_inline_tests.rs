//! Gate `process_exit`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn process_exit_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/process_exit.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !super::inline_gate::contains_inline_test_module_or_function(&src),
        "process_exit: move inline tests to crates/scanner/tests/"
    );
}
