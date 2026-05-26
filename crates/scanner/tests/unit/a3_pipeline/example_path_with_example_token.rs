use keyhog_scanner::context::CodeContext;
use keyhog_scanner::should_suppress_known_example_credential;

#[test]
fn fixtures_path_example_suppressed() {
    assert!(should_suppress_known_example_credential(
        "ghp_EXAMPLE_from_fixtures",
        Some("tests/fixtures/example.env"),
        CodeContext::Unknown,
    ));
}
