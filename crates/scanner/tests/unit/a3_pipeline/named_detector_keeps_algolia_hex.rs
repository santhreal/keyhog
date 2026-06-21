use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::named_detector_suppressed;

#[test]
fn algolia_32hex_not_suppressed_when_named() {
    assert!(!named_detector_suppressed(
        "0123456789abcdef0123456789abcdef",
        None,
        CodeContext::Assignment,
        None,
        "algolia-admin-key",
    ));
}
