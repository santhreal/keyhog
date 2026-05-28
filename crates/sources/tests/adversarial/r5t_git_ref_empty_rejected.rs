//! R5-T git adversarial: empty git ref rejected.

#[cfg(feature = "git")]
#[test]
fn r5t_git_ref_empty_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitDiffSource;
    let (_guard, repo) = crate::support::git::init_repo();
    crate::support::git::commit(&repo, "a.txt", "x=1\n", "init");
    let err = GitDiffSource::new(repo, "   ")
        .chunks()
        .next()
        .unwrap()
        .expect_err("empty ref must fail");
    assert!(err.to_string().contains("cannot be empty"));
}

#[cfg(not(feature = "git"))]
#[test]
fn r5t_git_ref_empty_rejected() {}
