use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn long_x_mask_suppressed() {
    assert!(known_example_suppressed(
        "password_XXXXXXX",
        None,
        CodeContext::Assignment,
    ));
}
