//! Corrupt `.git/HEAD` must fail cleanly without panic.

#[cfg(feature = "git")]
#[test]
fn corrupt_git_head_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;

    let (_temp, repo) = crate::support::git::init_repo();
    crate::support::git::commit(
        &repo,
        "live.env",
        "KEY=ghp_corruptHeadLiveRef00000000001\n",
        "live ref survives corrupt HEAD",
    );
    let git_dir = repo.join(".git");
    std::fs::write(git_dir.join("HEAD"), b"not-a-valid-ref\n").expect("corrupt head");

    let err = GitSource::new(repo)
        .chunks()
        .next()
        .unwrap()
        .expect_err("corrupt HEAD must error");
    let msg = err.to_string();
    assert!(
        msg.contains("failed to read git HEAD while collecting live blob set"),
        "corrupt HEAD must fail before live-ref blobs are mislabeled as history; got {msg}"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn corrupt_git_head_rejected() {}
