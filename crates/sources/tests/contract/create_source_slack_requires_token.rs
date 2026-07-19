//! Slack source factory must require token parameter.

#[test]
fn create_source_slack_requires_token() {
    match keyhog_sources::create_source("slack", None) {
        Err(keyhog_core::SourceError::InvalidConfiguration {
            source_name,
            detail,
        }) => {
            assert_eq!(source_name, "slack");
            assert_eq!(detail, "a token is required");
        }
        Err(err) => panic!("slack returned the wrong error: {err}"),
        Ok(_) => panic!("slack without token must return Err"),
    }
}
