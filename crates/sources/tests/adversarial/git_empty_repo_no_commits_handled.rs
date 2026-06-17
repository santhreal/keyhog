//! Empty git repository (no commits) must yield zero chunks without panic.

#[cfg(feature = "git")]
#[test]
fn git_empty_repo_no_commits_handled() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;
    use std::process::Command;

    let dir = tempfile::tempdir().expect("tempdir");
    Command::new("git")
        .args(["init", "-b", "main"])
        .current_dir(dir.path())
        .output()
        .expect("git init");

    let chunks: Vec<_> = GitSource::new(dir.path().to_path_buf()).chunks().collect();

    assert!(
        chunks.is_empty(),
        "empty repo must yield no chunks (not an error iterator); got {chunks:?}"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_empty_repo_no_commits_handled() {}
