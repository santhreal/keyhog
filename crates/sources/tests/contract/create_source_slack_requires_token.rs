//! Slack source factory must require token parameter.

#[test]
fn create_source_slack_requires_token() {
    match keyhog_sources::create_source("slack", None) {
        Err(err) => assert!(err.to_string().contains("requires a token"), "got {err}"),
        Ok(_) => panic!("slack without token must return Err"),
    }
}
