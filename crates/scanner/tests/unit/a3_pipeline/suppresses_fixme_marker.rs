use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn fixme_marker_suppresses() {
    assert!(known_example_suppressed(
        "FIXME_set_secret",
        None,
        CodeContext::Comment,
    ));
}
