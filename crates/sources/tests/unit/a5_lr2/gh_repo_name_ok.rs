#[test]
fn gh_repo_name_ok() {
    assert!(keyhog_sources::testing::validate_repo_name("keyhog").is_ok());
}
