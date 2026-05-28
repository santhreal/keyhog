#[test]
fn http_ua_has_version() {assert!(keyhog_sources::testing::user_agent(None).contains(env!("CARGO_PKG_VERSION")));}
