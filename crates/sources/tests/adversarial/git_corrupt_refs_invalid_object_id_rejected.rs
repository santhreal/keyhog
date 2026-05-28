//! Invalid object id in refs/heads must error cleanly.

#[cfg(feature = "git")]
#[test]
fn git_corrupt_refs_invalid_object_id_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;
    let dir = tempfile::tempdir().expect("tempdir");
    let git_dir = dir.path().join(".git");
    std::fs::create_dir_all(git_dir.join("refs/heads")).expect("refs");
    std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").expect("head");
    std::fs::write(git_dir.join("refs/heads/main"), "not-a-valid-object\n").expect("ref");

    let err = GitSource::new(dir.path().to_path_buf())
        .chunks()
        .next()
        .unwrap()
        .expect_err("invalid object id must fail");
    assert!(!err.to_string().is_empty());
}

#[cfg(not(feature = "git"))]
#[test]
fn git_corrupt_refs_invalid_object_id_rejected() {}
