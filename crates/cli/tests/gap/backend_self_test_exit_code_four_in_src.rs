//! Contract gate: backend subcommand defines self-test failure exit 4.

#[test]
fn backend_self_test_exit_code_four_in_src() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/subcommands/backend.rs"));
    assert!(src.contains("const EXIT_SELF_TEST_FAILED: u8 = 4"));
}
