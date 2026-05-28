//! R5-T git adversarial: repo path with control char rejected.

#[cfg(feature = "git")]
#[test]
fn r5t_git_repo_path_control_char_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;
    let bad = std::path::PathBuf::from("bad\x07repo");
    let err = GitSource::new(bad)
        .chunks()
        .next()
        .unwrap()
        .expect_err("control char path must fail");
    assert!(err.to_string().contains("unsafe characters"));
}

#[cfg(not(feature = "git"))]
#[test]
fn r5t_git_repo_path_control_char_rejected() {}
