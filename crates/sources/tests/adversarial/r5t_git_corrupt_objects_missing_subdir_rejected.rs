//! R5-T git adversarial: missing objects/ subdir rejected.

#[cfg(feature = "git")]
#[test]
fn r5t_git_corrupt_objects_missing_subdir_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;
    let dir = tempfile::tempdir().expect("tempdir");
    let git_dir = dir.path().join(".git");
    std::fs::create_dir_all(&git_dir).expect("mkdir");
    std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").expect("head");
    std::fs::write(git_dir.join("config"), "[core]\n\trepositoryformatversion = 0\n").expect("cfg");
    let err = GitSource::new(dir.path().to_path_buf())
        .chunks()
        .next()
        .unwrap()
        .expect_err("missing objects must fail");
    assert!(!err.to_string().is_empty());
}

#[cfg(not(feature = "git"))]
#[test]
fn r5t_git_corrupt_objects_missing_subdir_rejected() {}
