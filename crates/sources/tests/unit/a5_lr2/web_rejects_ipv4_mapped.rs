use keyhog_sources::testing::{SourceTestApi, TestApi};
#[test]
fn web_rejects_ipv4_mapped() {
    assert!(TestApi.is_disallowed_web_host("http://[::ffff:127.0.0.1]/"));
}
