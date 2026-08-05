use keyhog_sources::testing::{TestApi};
#[test]
fn gh_clone_https_ok() {
    assert!(TestApi.validate_clone_url("https://github.com/o/r.git").is_ok());
}
