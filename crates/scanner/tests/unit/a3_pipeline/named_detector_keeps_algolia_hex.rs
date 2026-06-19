use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_named_detector_finding;

#[test]
fn algolia_32hex_not_suppressed_when_named() {
    assert!(!should_suppress_named_detector_finding(
        "0123456789abcdef0123456789abcdef",
        None,
        CodeContext::Assignment,
        None,
        "algolia-admin-key",
    ));
}
