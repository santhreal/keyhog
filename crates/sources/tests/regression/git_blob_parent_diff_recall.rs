//! WHY: `--git-blobs` must still emit a credential that was committed and later
//! deleted when blob collection uses parent-tree diffs instead of full tree
//! rewalks. Newest-first history sees the deletion first; the deleted blob side
//! has to stay in the scan set or the competitive "added then removed" corpus
//! becomes a silent false negative.

use keyhog_core::Source;
use keyhog_sources::GitSource;
use std::process::Command;

fn git(root: &std::path::Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_AUTHOR_NAME", "KeyHog Test")
        .env("GIT_AUTHOR_EMAIL", "keyhog-test@example.invalid")
        .env("GIT_COMMITTER_NAME", "KeyHog Test")
        .env("GIT_COMMITTER_EMAIL", "keyhog-test@example.invalid")
        .output()
        .expect("run git fixture command");
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn git_blobs_recall_secret_added_then_removed_via_parent_diffs() {
    let repo = tempfile::tempdir().expect("create git fixture");
    git(repo.path(), &["init", "--quiet", "-b", "main"]);

    // Build a short flat history so parent-tree diffs are on the hot path:
    // several ordinary commits, then add+remove of a secret blob.
    for index in 0..8 {
        std::fs::write(
            repo.path().join(format!("f{index:02}.txt")),
            format!("ordinary fixture row {index}\n"),
        )
        .expect("write ordinary blob");
        git(repo.path(), &["add", &format!("f{index:02}.txt")]);
        git(
            repo.path(),
            &["commit", "--quiet", "-m", &format!("add f{index:02}")],
        );
    }

    const SECRET: &str =
        "GITHUB_TOKEN=ghp_parentDiffRecallFixture00000000000001\n";
    std::fs::write(repo.path().join("secrets.env"), SECRET).expect("write secret");
    git(repo.path(), &["add", "secrets.env"]);
    git(repo.path(), &["commit", "--quiet", "-m", "add secrets"]);

    git(repo.path(), &["rm", "--quiet", "secrets.env"]);
    git(repo.path(), &["commit", "--quiet", "-m", "remove secrets"]);

    assert!(
        !repo.path().join("secrets.env").exists(),
        "working tree must not retain the removed secret"
    );

    let rows = GitSource::new(repo.path().to_path_buf())
        .chunks()
        .collect::<Vec<_>>();
    let errors: Vec<_> = rows.iter().filter_map(|row| row.as_ref().err()).collect();
    assert!(
        errors.is_empty(),
        "complete fixture history must scan without gaps: {errors:?}"
    );
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    let secret_chunks: Vec<_> = chunks
        .iter()
        .filter(|chunk| chunk.data.contains("ghp_parentDiffRecallFixture"))
        .collect();
    assert!(
        !secret_chunks.is_empty(),
        "parent-tree diff collection must still emit the deleted secrets.env blob; got {} chunks",
        chunks.len()
    );
    assert!(
        secret_chunks.iter().any(|chunk| {
            chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|path| path.ends_with("secrets.env"))
        }),
        "recalled secret chunk must keep secrets.env path metadata"
    );
}
