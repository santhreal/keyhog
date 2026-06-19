use keyhog_sources::testing::{SourceTestApi, TestApi};
#[test]
fn web_accepts_example() {
    assert!(!TestApi.is_disallowed_web_host("https://example.com/"));
}
