//! Contract gate: backend subcommand defines self-test failure exit 4.

#[test]
fn backend_self_test_exit_code_four_in_src() {
    assert_eq!(keyhog::exit_codes::EXIT_BACKEND_SELF_TEST_FAILED, 4);
}
