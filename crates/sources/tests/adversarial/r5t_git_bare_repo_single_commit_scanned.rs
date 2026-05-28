//! R5-T git adversarial: bare repo with one commit yields chunks.

#[cfg(feature = "git")]
#[test]
fn r5t_git_bare_repo_single_commit_scanned() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;
    use std::process::Command;
    let dir = tempfile::tempdir().expect("tempdir");
    Command::new("git").args(["init", "--bare", "-q"]).current_dir(dir.path()).status().expect("init bare");
    let bare = dir.path().join("repo.git");
    std::fs::create_dir_all(bare.join("objects")).expect("objects");
    std::process::Command::new("git").args(["config", "user.email", "r5t@test"]).current_dir(&bare).status().unwrap();
    std::process::Command::new("git").args(["config", "user.name", "R5T"]).current_dir(&bare).status().unwrap();
    std::fs::write(bare.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    let work = tempfile::tempdir().expect("work");
    std::fs::write(work.path().join("secret.env"), "K=1\n").unwrap();
    Command::new("git").args(["--git-dir"]).arg(&bare).args(["--work-tree"]).arg(work.path()).args(["add", "secret.env"]).status().unwrap();
    Command::new("git").args(["--git-dir"]).arg(&bare).args(["--work-tree"]).arg(work.path()).args(["commit", "-m", "init", "-q"]).status().unwrap();
    let count = GitSource::new(bare).chunks().flatten().count();
    assert!(count >= 1, "bare repo with commit must yield chunks");
}

#[cfg(not(feature = "git"))]
#[test]
fn r5t_git_bare_repo_single_commit_scanned() {}
