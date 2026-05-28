//! Corrupt `.git/config` must fail without panic.

#[cfg(feature = "git")]
#[test]
fn git_corrupt_config_invalid_ini_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;
    let dir = tempfile::tempdir().expect("tempdir");
    let git_dir = dir.path().join(".git");
    std::fs::create_dir_all(&git_dir).expect("mkdir");
    std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").expect("head");
    std::fs::write(git_dir.join("config"), b"[core\n\trepositoryformatversion = not-a-number\n").expect("config");

    let err = GitSource::new(dir.path().to_path_buf())
        .chunks()
        .next()
        .unwrap()
        .expect_err("invalid config must fail");
    assert!(!err.to_string().is_empty());
}

#[cfg(not(feature = "git"))]
#[test]
fn git_corrupt_config_invalid_ini_rejected() {}
