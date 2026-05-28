//! Corrupt `.git/HEAD` must fail cleanly without panic.

#[cfg(feature = "git")]
#[test]
fn corrupt_git_head_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;

    let dir = tempfile::tempdir().expect("tempdir");
    let git_dir = dir.path().join(".git");
    std::fs::create_dir_all(&git_dir).expect("mkdir");
    std::fs::write(git_dir.join("HEAD"), b"not-a-valid-ref\n").expect("corrupt head");

    let err = GitSource::new(dir.path().to_path_buf())
        .chunks()
        .next()
        .unwrap()
        .expect_err("corrupt HEAD must error");
    let msg = err.to_string();
    assert!(
        !msg.is_empty(),
        "corrupt git repo must surface actionable error, not panic"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn corrupt_git_head_rejected() {}
