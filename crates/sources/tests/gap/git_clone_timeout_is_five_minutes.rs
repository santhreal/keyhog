//! GitHub org shallow clone budget must be centralized in timeouts.rs.

#[cfg(feature = "github")]
#[test]
fn git_clone_timeout_is_five_minutes() {
    assert_eq!(
        keyhog_sources::testing::git_clone_timeout(),
        std::time::Duration::from_secs(300)
    );
}

#[cfg(not(feature = "github"))]
#[test]
fn git_clone_timeout_requires_github_feature() {
    assert!(!cfg!(feature = "github"));
}
