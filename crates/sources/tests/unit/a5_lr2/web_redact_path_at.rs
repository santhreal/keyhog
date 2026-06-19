use keyhog_sources::testing::{SourceTestApi, TestApi};
#[test]
fn web_redact_path_at() {
    let u="https://example.com/users/@me"; assert_eq!(TestApi.redact_url(u), u);
}
