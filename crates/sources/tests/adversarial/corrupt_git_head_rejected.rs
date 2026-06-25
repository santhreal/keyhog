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
    // A corrupt HEAD must abort the scan LOUDLY before any live-ref blob is
    // emitted, so a credential live in HEAD can never be mislabeled as the
    // lower-severity `git/history`. Two defenses satisfy that, and which one
    // fires first depends on enumeration order: the gix live-blob-set guard
    // (`collect_head_blob_path_set`) or the earlier reachable-tag enumeration,
    // which `git` itself rejects because an unparseable HEAD makes the whole
    // repository invalid. Either proves the scan failed closed (the
    // `expect_err` above already proved no Ok blob was yielded first).
    assert!(
        msg.contains("failed to read git HEAD while collecting live blob set")
            || msg.contains("for-each-ref failed")
            || msg.contains("not a git repository"),
        "corrupt HEAD must fail loud before any live-ref blob is emitted; got {msg}"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn corrupt_git_head_rejected() {}
