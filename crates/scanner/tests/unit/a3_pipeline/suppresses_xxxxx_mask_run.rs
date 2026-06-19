use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_known_example_credential;

#[test]
fn long_x_mask_suppressed() {
    assert!(should_suppress_known_example_credential(
        "password_XXXXXXX",
        None,
        CodeContext::Assignment,
    ));
}
