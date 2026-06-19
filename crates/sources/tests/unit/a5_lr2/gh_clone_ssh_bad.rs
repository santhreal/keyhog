use keyhog_sources::testing::{SourceTestApi, TestApi};
#[test]
fn gh_clone_ssh_bad() {
    assert!(TestApi.validate_clone_url("git@github.com:o/r.git").is_err());
}
