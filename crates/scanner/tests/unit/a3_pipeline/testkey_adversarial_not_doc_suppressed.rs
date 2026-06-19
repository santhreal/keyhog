use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_known_example_credential;

#[test]
fn testkey_fixture_not_suppressed() {
    assert!(!should_suppress_known_example_credential(
        "TESTKEY_aK7xP9mQ2wE5rT8yU1iO",
        None,
        CodeContext::Unknown,
    ));
}
