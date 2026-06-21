use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn uuid_v4_suppressed_for_generic_path() {
    assert!(known_example_suppressed(
        "550e8400-e29b-41d4-a716-446655440000",
        None,
        CodeContext::Unknown,
    ));
}
