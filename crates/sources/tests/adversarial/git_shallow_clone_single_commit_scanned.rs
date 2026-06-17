//! Shallow git clone (depth 1) must still scan without panic.

#[cfg(feature = "git")]
#[test]
fn git_shallow_clone_single_commit_scanned() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;
    use std::process::Command;

    let origin = tempfile::tempdir().expect("origin");
    assert!(Command::new("git")
        .args(["init", "-b", "main"])
        .current_dir(origin.path())
        .status()
        .expect("git init")
        .success());
    std::fs::write(
        origin.path().join("secret.env"),
        "SHALLOW=AKIAQYLPMN5HFIQR7XYA\n",
    )
    .expect("write");
    assert!(Command::new("git")
        .args(["add", "secret.env"])
        .current_dir(origin.path())
        .status()
        .expect("git add")
        .success());
    assert!(Command::new("git")
        .args([
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=test",
            "commit",
            "-m",
            "init"
        ])
        .current_dir(origin.path())
        .status()
        .expect("git commit")
        .success());

    let shallow = tempfile::tempdir().expect("shallow");
    let origin_url = format!("file://{}", origin.path().display());
    assert!(Command::new("git")
        .args(["clone", "--depth", "1", &origin_url, "."])
        .current_dir(shallow.path())
        .status()
        .expect("git clone")
        .success());

    let bodies: Vec<String> = GitSource::new(shallow.path().to_path_buf())
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();
    assert!(
        bodies.iter().any(|b| b.contains("SHALLOW=AKIA")),
        "shallow clone must still surface tracked secrets; got {bodies:?}"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_shallow_clone_single_commit_scanned() {}
