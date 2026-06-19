use keyhog_sources::testing::{SourceTestApi, TestApi};
#[test]
fn http_ua_suffix() {assert!(TestApi.user_agent(Some("web")).contains("(web)"));}
