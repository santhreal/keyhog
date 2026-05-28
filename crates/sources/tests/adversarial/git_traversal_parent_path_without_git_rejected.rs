//! Parent traversal path without `.git` must be rejected.

#[cfg(feature = "git")]
#[test]
fn git_traversal_parent_path_without_git_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("plain.txt"), "x\n").expect("plain");
    let nested = dir.path().join("nested");
    std::fs::create_dir(&nested).expect("mkdir");

    let err = GitSource::new(nested.join("..").join("..").join("etc"))
        .chunks()
        .next()
        .unwrap()
        .expect_err("traversal without git metadata must fail");
    assert!(
        err.to_string().contains("not a git repository")
            || err.to_string().contains("failed to canonicalize"),
        "got {err}"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_traversal_parent_path_without_git_rejected() {}
