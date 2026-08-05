use keyhog_sources::testing::{TestApi};
#[test]
fn web_redact_userinfo() {
    assert_eq!(TestApi.redact_url("https://u:SECRET@host/p"), "https://***@host/p");
}
