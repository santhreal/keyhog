use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn fixtures_path_example_suppressed() {
    assert!(known_example_suppressed(
        "ghp_EXAMPLE_from_fixtures",
        Some("tests/fixtures/example.env"),
        CodeContext::Unknown,
    ));
}
