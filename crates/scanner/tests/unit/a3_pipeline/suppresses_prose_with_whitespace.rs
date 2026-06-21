use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn multiword_prose_suppressed() {
    assert!(known_example_suppressed(
        "Session opened with handle abcdef0123456789 see documentation",
        None,
        CodeContext::Unknown,
    ));
}
