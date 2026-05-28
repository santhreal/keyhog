//! R5-T git adversarial: diff against missing base ref errors.

#[cfg(feature = "git")]
#[test]
fn r5t_git_diff_nonexistent_base_ref_errors() {
    use keyhog_core::Source;
    use keyhog_sources::GitDiffSource;
    let (_guard, repo) = crate::support::git::init_repo();
    crate::support::git::commit(&repo, "a.txt", "x=1\n", "init");
    let err = GitDiffSource::new(repo, "no-such-ref-r5t")
        .chunks()
        .next()
        .unwrap()
        .expect_err("missing ref must fail");
    assert!(err.to_string().contains("not found"));
}

#[cfg(not(feature = "git"))]
#[test]
fn r5t_git_diff_nonexistent_base_ref_errors() {}
