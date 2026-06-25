//! Shallow git clone (depth 1) must still scan without panic.

use crate::support::split_chunk_results;
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

    let source = GitSource::new(shallow.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "shallow clone scan should not emit SourceError rows: {errors:?}"
    );
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("SHALLOW=AKIA")
                && chunk
                    .metadata
                    .path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("secret.env"))),
        "shallow clone must still surface tracked secrets with path metadata; got {chunks:?}"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_shallow_clone_single_commit_scanned() {}
