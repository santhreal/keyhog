#[test]
fn gh_repo_traversal_bad() {
    assert!(keyhog_sources::testing::validate_repo_name("../x").is_err());
}
