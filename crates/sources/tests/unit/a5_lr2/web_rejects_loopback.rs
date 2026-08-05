use keyhog_sources::testing::{TestApi};
#[test]
fn web_rejects_loopback() {
    assert!(TestApi.is_disallowed_web_host("http://127.0.0.1/"));
}
