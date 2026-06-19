use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_known_example_credential;

#[test]
fn office_license_shape_suppressed() {
    assert!(should_suppress_known_example_credential(
        "ABCDE-12345-FGHIJ-67890-KLMNO",
        None,
        CodeContext::Unknown,
    ));
}
