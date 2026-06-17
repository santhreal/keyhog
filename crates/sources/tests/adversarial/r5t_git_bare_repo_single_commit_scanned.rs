//! R5-T git adversarial: bare repo with one commit yields chunks.

#[cfg(feature = "git")]
#[test]
fn r5t_git_bare_repo_single_commit_scanned() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;
    use std::process::Command;
    let dir = tempfile::tempdir().expect("tempdir");
    let bare = dir.path().join("repo.git");
    let status = Command::new("git")
        .args(["init", "--bare", "-q"])
        .arg(&bare)
        .status()
        .expect("init bare");
    assert!(status.success(), "git init --bare failed");
    let status = Command::new("git")
        .args(["config", "user.email", "r5t@test"])
        .current_dir(&bare)
        .status()
        .unwrap();
    assert!(status.success(), "git config user.email failed");
    let status = Command::new("git")
        .args(["config", "user.name", "R5T"])
        .current_dir(&bare)
        .status()
        .unwrap();
    assert!(status.success(), "git config user.name failed");
    std::fs::write(bare.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    let work = tempfile::tempdir().expect("work");
    std::fs::write(work.path().join("secret.env"), "K=1\n").unwrap();
    let status = Command::new("git")
        .args(["--git-dir"])
        .arg(&bare)
        .args(["--work-tree"])
        .arg(work.path())
        .args(["add", "secret.env"])
        .status()
        .unwrap();
    assert!(status.success(), "git add failed");
    let status = Command::new("git")
        .args(["--git-dir"])
        .arg(&bare)
        .args(["--work-tree"])
        .arg(work.path())
        .args(["commit", "-m", "init", "-q"])
        .status()
        .unwrap();
    assert!(status.success(), "git commit failed");
    let chunks: Vec<_> = GitSource::new(bare)
        .chunks()
        .map(|chunk| chunk.expect("bare git repo scan must not emit source errors"))
        .collect();
    assert!(
        chunks.iter().any(|chunk| chunk.data.contains("K=1")),
        "bare repo with commit must yield the committed file; chunks={chunks:?}"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn r5t_git_bare_repo_single_commit_scanned() {}
