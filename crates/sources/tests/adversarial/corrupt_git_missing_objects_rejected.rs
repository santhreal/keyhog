//! Git repo with missing object store must error without panic.

#[cfg(feature = "git")]
#[test]
fn corrupt_git_missing_objects_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;

    let dir = tempfile::tempdir().expect("tempdir");
    let git_dir = dir.path().join(".git");
    std::fs::create_dir_all(&git_dir).expect("mkdir");
    std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").expect("head");
    std::fs::create_dir_all(git_dir.join("refs/heads")).expect("refs");
    std::fs::write(
        git_dir.join("refs/heads/main"),
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n",
    )
    .expect("ref");

    let err = GitSource::new(dir.path().to_path_buf())
        .chunks()
        .next()
        .unwrap()
        .expect_err("missing objects must fail");
    assert!(
        !err.to_string().is_empty(),
        "missing git objects must not panic silently"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn corrupt_git_missing_objects_rejected() {}
