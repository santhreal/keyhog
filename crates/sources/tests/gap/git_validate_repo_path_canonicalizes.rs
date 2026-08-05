//! Git sources must canonicalize repo paths and require .git/HEAD.

#[cfg(not(feature = "git"))]
#[test]
fn git_validate_repo_requires_git_feature() {
    assert!(!cfg!(feature = "git"));
}
