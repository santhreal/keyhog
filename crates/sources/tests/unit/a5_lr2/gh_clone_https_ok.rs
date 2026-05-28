#[test]
fn gh_clone_https_ok() {
    assert!(keyhog_sources::testing::validate_clone_url("https://github.com/o/r.git").is_ok());
}
