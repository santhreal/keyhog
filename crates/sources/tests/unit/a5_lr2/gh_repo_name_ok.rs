use keyhog_sources::testing::{SourceTestApi, TestApi};
#[test]
fn gh_repo_name_ok() {
    assert!(TestApi.validate_repo_name("keyhog").is_ok());
}
