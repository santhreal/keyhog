use keyhog_sources::testing::{SourceTestApi, TestApi};
#[test]
fn http_ua_has_version() {assert!(TestApi.user_agent(None).contains(env!("CARGO_PKG_VERSION")));}
