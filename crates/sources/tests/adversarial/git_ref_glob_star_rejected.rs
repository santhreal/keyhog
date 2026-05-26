//! Unsafe git ref names with glob metacharacters must error.

#[cfg(feature = "git")]
#[test]
fn git_ref_glob_star_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitDiffSource;

    let (_guard, repo) = crate::support::git::init_repo();
    crate::support::git::commit(
        &repo, "a.txt", "x=1
", "init",
    );

    let source = GitDiffSource::new(repo, "main*evil");
    let err = source
        .chunks()
        .next()
        .expect("one iterator item")
        .expect_err("glob ref must fail");
    assert!(err.to_string().contains("unsafe git ref"), "got {err}");
}
