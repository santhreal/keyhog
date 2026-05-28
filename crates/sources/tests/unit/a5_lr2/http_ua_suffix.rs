#[test]
fn http_ua_suffix() {assert!(keyhog_sources::testing::user_agent(Some("web")).contains("(web)"));}
