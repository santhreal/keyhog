#[test]
fn gh_clone_ssh_bad() {
    assert!(keyhog_sources::testing::validate_clone_url("git@github.com:o/r.git").is_err());
}
