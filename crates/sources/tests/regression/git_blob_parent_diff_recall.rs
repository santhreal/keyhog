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

    const SECRET: &str = "GITHUB_TOKEN=ghp_parentDiffRecallFixture00000000000001\n";
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

#[test]
fn git_blobs_recall_secret_when_earlier_tree_is_reused() {
    let repo = tempfile::tempdir().expect("create git fixture");
    git(repo.path(), &["init", "--quiet", "-b", "main"]);

    const SECRET: &str = "GITHUB_TOKEN=ghp_parentDiffTreeReuseFixture0000000001\n";
    std::fs::write(repo.path().join("keep.env"), SECRET).expect("write secret");
    git(repo.path(), &["add", "keep.env"]);
    git(repo.path(), &["commit", "--quiet", "-m", "add keep secret"]);

    std::fs::write(repo.path().join("extra.txt"), "temporary side file\n").expect("write extra");
    git(repo.path(), &["add", "extra.txt"]);
    git(repo.path(), &["commit", "--quiet", "-m", "add extra"]);

    // Revert the tree back to the first commit so the same root tree oid reappears
    // after a parent-diff visit that did not fully enumerate it.
    git(repo.path(), &["rm", "--quiet", "extra.txt"]);
    git(
        repo.path(),
        &[
            "commit",
            "--quiet",
            "-m",
            "remove extra; reuse earlier tree",
        ],
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
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("ghp_parentDiffTreeReuseFixture")),
        "reused earlier tree must still emit keep.env after parent-diff visits; got {} chunks",
        chunks.len()
    );
}

#[test]
fn git_blobs_recall_untouched_tip_blob_under_max_commits() {
    let repo = tempfile::tempdir().expect("create git fixture");
    git(repo.path(), &["init", "--quiet", "-b", "main"]);

    const SECRET: &str = "GITHUB_TOKEN=ghp_parentDiffMaxCommitsTipFixture00000001\n";
    std::fs::write(repo.path().join("keep.env"), SECRET).expect("write secret");
    git(repo.path(), &["add", "keep.env"]);
    git(repo.path(), &["commit", "--quiet", "-m", "add keep secret"]);

    for index in 0..6 {
        std::fs::write(
            repo.path().join(format!("later-{index}.txt")),
            format!("later row {index}\n"),
        )
        .expect("write later blob");
        git(repo.path(), &["add", &format!("later-{index}.txt")]);
        git(
            repo.path(),
            &["commit", "--quiet", "-m", &format!("later {index}")],
        );
    }

    // Window excludes the introducing commit; tip full-walk must still emit keep.env.
    let rows = GitSource::new(repo.path().to_path_buf())
        .with_max_commits(3)
        .chunks()
        .collect::<Vec<_>>();
    let errors: Vec<_> = rows.iter().filter_map(|row| row.as_ref().err()).collect();
    assert!(
        errors.is_empty(),
        "complete fixture history must scan without gaps: {errors:?}"
    );
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("ghp_parentDiffMaxCommitsTipFixture")),
        "max-commits tip full-walk must still emit untouched keep.env; got {} chunks",
        chunks.len()
    );
}

#[test]
fn git_blobs_recall_side_branch_tip_under_max_commits() {
    let repo = tempfile::tempdir().expect("create git fixture");
    git(repo.path(), &["init", "--quiet", "-b", "main"]);

    std::fs::write(repo.path().join("base.txt"), "base\n").expect("write base");
    git(repo.path(), &["add", "base.txt"]);
    git(repo.path(), &["commit", "--quiet", "-m", "base"]);

    git(repo.path(), &["checkout", "--quiet", "-b", "side"]);
    const SECRET: &str = "GITHUB_TOKEN=ghp_parentDiffSideBranchTipFixture0000001\n";
    std::fs::write(repo.path().join("side-secret.env"), SECRET).expect("write side secret");
    git(repo.path(), &["add", "side-secret.env"]);
    git(repo.path(), &["commit", "--quiet", "-m", "add side secret"]);
    std::fs::write(repo.path().join("side-noise.txt"), "noise\n").expect("write side noise");
    git(repo.path(), &["add", "side-noise.txt"]);
    git(repo.path(), &["commit", "--quiet", "-m", "side noise tip"]);

    git(repo.path(), &["checkout", "--quiet", "main"]);
    for index in 0..6 {
        std::fs::write(
            repo.path().join(format!("main-{index}.txt")),
            format!("main row {index}\n"),
        )
        .expect("write main blob");
        git(repo.path(), &["add", &format!("main-{index}.txt")]);
        git(
            repo.path(),
            &["commit", "--quiet", "-m", &format!("main {index}")],
        );
    }

    // Newest commits are on main; the side tip is still inside the window but
    // older than main tip. Parent-diff on the side tip alone would only see
    // side-noise.txt; full-walking every ref tip must still emit the secret.
    let rows = GitSource::new(repo.path().to_path_buf())
        .with_max_commits(8)
        .chunks()
        .collect::<Vec<_>>();
    let errors: Vec<_> = rows.iter().filter_map(|row| row.as_ref().err()).collect();
    assert!(
        errors.is_empty(),
        "complete fixture history must scan without gaps: {errors:?}"
    );
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("ghp_parentDiffSideBranchTipFixture")),
        "side-branch tip full-walk must emit untouched side-secret.env; got {} chunks",
        chunks.len()
    );
}

#[test]
fn git_blobs_recall_detached_head_tip_under_max_commits() {
    let repo = tempfile::tempdir().expect("create git fixture");
    git(repo.path(), &["init", "--quiet", "-b", "main"]);

    const SECRET: &str = "GITHUB_TOKEN=ghp_parentDiffDetachedHeadTipFixture000001\n";
    std::fs::write(repo.path().join("keep.env"), SECRET).expect("write secret");
    git(repo.path(), &["add", "keep.env"]);
    git(repo.path(), &["commit", "--quiet", "-m", "add keep secret"]);
    let tip = String::from_utf8(
        std::process::Command::new("git")
            .args([
                "-C",
                repo.path().to_str().expect("utf8 path"),
                "rev-parse",
                "HEAD",
            ])
            .output()
            .expect("rev-parse tip")
            .stdout,
    )
    .expect("utf8 tip")
    .trim()
    .to_string();

    for index in 0..5 {
        std::fs::write(
            repo.path().join(format!("later-{index}.txt")),
            format!("later row {index}\n"),
        )
        .expect("write later blob");
        git(repo.path(), &["add", &format!("later-{index}.txt")]);
        git(
            repo.path(),
            &["commit", "--quiet", "-m", &format!("later {index}")],
        );
    }

    // Detach onto the introducing tip so HEAD is not a named branch tip.
    git(repo.path(), &["checkout", "--quiet", "--detach", &tip]);
    for index in 0..4 {
        std::fs::write(
            repo.path().join(format!("detached-{index}.txt")),
            format!("detached row {index}\n"),
        )
        .expect("write detached blob");
        git(repo.path(), &["add", &format!("detached-{index}.txt")]);
        git(
            repo.path(),
            &["commit", "--quiet", "-m", &format!("detached {index}")],
        );
    }

    let rows = GitSource::new(repo.path().to_path_buf())
        .with_max_commits(4)
        .chunks()
        .collect::<Vec<_>>();
    let errors: Vec<_> = rows.iter().filter_map(|row| row.as_ref().err()).collect();
    assert!(
        errors.is_empty(),
        "complete fixture history must scan without gaps: {errors:?}"
    );
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("ghp_parentDiffDetachedHeadTipFixture")),
        "detached HEAD tip full-walk must emit untouched keep.env; got {} chunks",
        chunks.len()
    );
}

#[test]
fn git_blobs_skip_excluded_unsupported_diff_entries() {
    // Parent-diff collection must honor default excludes before unsupported-mode
    // coverage gaps, matching the full tree walk. A symlink under node_modules/
    // must not flip the scan to partial coverage.
    let repo = tempfile::tempdir().expect("create git fixture");
    git(repo.path(), &["init", "--quiet", "-b", "main"]);
    std::fs::write(repo.path().join("keep.txt"), "ok\n").expect("write keep");
    git(repo.path(), &["add", "keep.txt"]);
    git(repo.path(), &["commit", "--quiet", "-m", "seed"]);

    std::fs::create_dir_all(repo.path().join("node_modules")).expect("mkdir node_modules");
    std::os::unix::fs::symlink("../keep.txt", repo.path().join("node_modules/link"))
        .expect("symlink under node_modules");
    git(repo.path(), &["add", "node_modules/link"]);
    git(
        repo.path(),
        &["commit", "--quiet", "-m", "add excluded symlink"],
    );

    let rows = GitSource::new(repo.path().to_path_buf())
        .chunks()
        .collect::<Vec<_>>();
    let errors: Vec<_> = rows.iter().filter_map(|row| row.as_ref().err()).collect();
    assert!(
        errors.is_empty(),
        "excluded unsupported diff entries must not become coverage gaps: {errors:?}"
    );
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks.iter().any(|chunk| chunk.data.contains("ok")),
        "seed blob should still be scanned"
    );
}

#[test]
fn git_blobs_recall_custom_ref_tip_under_max_commits() {
    // Same shape as the side-branch tip test, but the tip lives only under
    // refs/pull (outside heads/tags/remotes/stash) so for-each-ref must cover
    // every refs/ namespace.
    let repo = tempfile::tempdir().expect("create git fixture");
    git(repo.path(), &["init", "--quiet", "-b", "main"]);

    std::fs::write(repo.path().join("base.txt"), "base\n").expect("write base");
    git(repo.path(), &["add", "base.txt"]);
    git(repo.path(), &["commit", "--quiet", "-m", "base"]);

    git(repo.path(), &["checkout", "--quiet", "-b", "side"]);
    const SECRET: &str = "GITHUB_TOKEN=ghp_customRefTipFixture000000000000001\n";
    std::fs::write(repo.path().join("side-secret.env"), SECRET).expect("write side secret");
    git(repo.path(), &["add", "side-secret.env"]);
    git(repo.path(), &["commit", "--quiet", "-m", "add side secret"]);
    std::fs::write(repo.path().join("side-noise.txt"), "noise\n").expect("write side noise");
    git(repo.path(), &["add", "side-noise.txt"]);
    git(repo.path(), &["commit", "--quiet", "-m", "side noise tip"]);
    let tip = String::from_utf8(
        std::process::Command::new("git")
            .args(["-C", repo.path().to_str().unwrap(), "rev-parse", "HEAD"])
            .output()
            .expect("rev-parse")
            .stdout,
    )
    .expect("utf8")
    .trim()
    .to_string();
    git(repo.path(), &["update-ref", "refs/pull/1/head", &tip]);
    // Drop the heads ref so only the custom namespace keeps the tip alive.
    git(repo.path(), &["checkout", "--quiet", "main"]);
    git(repo.path(), &["branch", "--quiet", "-D", "side"]);

    for index in 0..6 {
        std::fs::write(
            repo.path().join(format!("main-{index}.txt")),
            format!("main row {index}\n"),
        )
        .expect("write main blob");
        git(repo.path(), &["add", &format!("main-{index}.txt")]);
        git(
            repo.path(),
            &["commit", "--quiet", "-m", &format!("main {index}")],
        );
    }

    let rows = GitSource::new(repo.path().to_path_buf())
        .with_max_commits(8)
        .chunks()
        .collect::<Vec<_>>();
    let errors: Vec<_> = rows.iter().filter_map(|row| row.as_ref().err()).collect();
    assert!(
        errors.is_empty(),
        "complete fixture history must scan without gaps: {errors:?}"
    );
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("ghp_customRefTipFixture")),
        "custom refs/pull tip full-walk must emit untouched side-secret.env; got {} chunks",
        chunks.len()
    );
}
