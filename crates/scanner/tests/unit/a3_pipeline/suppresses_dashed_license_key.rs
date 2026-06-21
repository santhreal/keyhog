use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn office_license_shape_suppressed() {
    assert!(known_example_suppressed(
        "ABCDE-12345-FGHIJ-67890-KLMNO",
        None,
        CodeContext::Unknown,
    ));
}
