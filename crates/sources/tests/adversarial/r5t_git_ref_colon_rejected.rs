//! R5-T git adversarial: ref names with colon rejected.

#[cfg(feature = "git")]
#[test]
fn r5t_git_ref_colon_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitDiffSource;
    let (_guard, repo) = crate::support::git::init_repo();
    crate::support::git::commit(&repo, "a.txt", "x=1\n", "init");
    let err = GitDiffSource::new(repo, "main:evil")
        .chunks()
        .next()
        .unwrap()
        .expect_err("colon ref must fail");
    assert!(err.to_string().contains("unsafe git ref"));
}

#[cfg(not(feature = "git"))]
#[test]
fn r5t_git_ref_colon_rejected() {}
