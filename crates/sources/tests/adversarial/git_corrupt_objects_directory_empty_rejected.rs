//! Git repo with empty objects store must fail cleanly.

#[cfg(feature = "git")]
#[test]
fn git_corrupt_objects_directory_empty_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;
    let dir = tempfile::tempdir().expect("tempdir");
    let git_dir = dir.path().join(".git");
    std::fs::create_dir_all(git_dir.join("objects")).expect("objects");
    std::fs::create_dir_all(git_dir.join("refs/heads")).expect("refs");
    std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").expect("head");
    std::fs::write(git_dir.join("refs/heads/main"), "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n").expect("ref");

    let source = GitSource::new(dir.path().to_path_buf());
    let mut iter = source.chunks();
    match iter.next() {
        Some(Err(e)) => assert!(!e.to_string().is_empty()),
        None => {} // git log fails; empty iterator is acceptable (no panic)
        Some(Ok(_)) => panic!("missing git objects must not yield readable chunks"),
    }
}

#[cfg(not(feature = "git"))]
#[test]
fn git_corrupt_objects_directory_empty_rejected() {}
