use keyhog_sources::testing::{TestApi};
#[test]
fn http_ua_suffix() {assert!(TestApi.user_agent(Some("web")).contains("(web)"));}
