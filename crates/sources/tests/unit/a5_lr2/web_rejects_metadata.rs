use keyhog_sources::testing::{TestApi};
#[test]
fn web_rejects_metadata() {
    assert!(TestApi.is_disallowed_web_host("http://169.254.169.254/latest/meta-data/"));
}
