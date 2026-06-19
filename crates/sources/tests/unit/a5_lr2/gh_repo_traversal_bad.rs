use keyhog_sources::testing::{SourceTestApi, TestApi};
#[test]
fn gh_repo_traversal_bad() {
    assert!(TestApi.validate_repo_name("../x").is_err());
}
