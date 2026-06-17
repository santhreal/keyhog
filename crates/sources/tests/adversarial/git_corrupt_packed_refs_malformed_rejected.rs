//! Malformed packed-refs must not panic git source.

#[cfg(feature = "git")]
#[test]
fn git_corrupt_packed_refs_malformed_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;
    let dir = tempfile::tempdir().expect("tempdir");
    let git_dir = dir.path().join(".git");
    std::fs::create_dir_all(git_dir.join("refs/heads")).expect("refs");
    std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").expect("head");
    std::fs::write(
        git_dir.join("refs/heads/main"),
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n",
    )
    .expect("ref");
    std::fs::write(
        git_dir.join("packed-refs"),
        b"# pack-refs with headers\n^not-a-ref\n",
    )
    .expect("packed");

    let err = GitSource::new(dir.path().to_path_buf())
        .chunks()
        .next()
        .unwrap()
        .expect_err("malformed packed-refs must fail");
    assert!(!err.to_string().is_empty());
}

#[cfg(not(feature = "git"))]
#[test]
fn git_corrupt_packed_refs_malformed_rejected() {}
