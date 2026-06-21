use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn testkey_fixture_not_suppressed() {
    assert!(!known_example_suppressed(
        "TESTKEY_aK7xP9mQ2wE5rT8yU1iO",
        None,
        CodeContext::Unknown,
    ));
}
