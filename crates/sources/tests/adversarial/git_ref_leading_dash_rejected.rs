//! Git ref names starting with - must be rejected.

#[cfg(feature = "git")]
#[test]
fn git_ref_leading_dash_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitDiffSource;

    let (_guard, repo) = crate::support::git::init_repo();
    crate::support::git::commit(&repo, "a.txt", "x=1
", "init");

    let source = GitDiffSource::new(repo, "-evil");
    let err = source.chunks().next().unwrap().expect_err("dash ref must fail");
    assert!(err.to_string().contains("unsafe git ref"));
}
