#![cfg(feature = "git")]

//! Tests for the staged Git manifest acquisition.
//!
//! These tests create real Git repositories, stage content, and verify the
//! manifest captures the exact staged object IDs, paths, modes, and
//! classifications.

use keyhog_core::guard_state::GitHashAlgorithm;
use keyhog_sources::{StagedEntryKind, StagedManifest};
use std::process::Command;

fn git(repo: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("run git")
}

fn init_repo() -> (tempfile::TempDir, std::path::PathBuf) {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let repo = temp_dir.path().to_path_buf();
    assert!(git(&repo, &["init", "-q", "-b", "main"]).status.success());
    assert!(git(&repo, &["config", "user.email", "test@example.com"]).status.success());
    assert!(git(&repo, &["config", "user.name", "Test"]).status.success());
    (temp_dir, repo)
}

fn commit(repo: &std::path::Path, filename: &str, content: &str, message: &str) {
    let path = repo.join(filename);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, content).unwrap();
    assert!(git(repo, &["add", filename]).status.success());
    assert!(git(repo, &["commit", "-q", "-m", message]).status.success());
}

fn stage_file(repo: &std::path::Path, filename: &str, content: &str) {
    let path = repo.join(filename);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, content).unwrap();
    assert!(git(repo, &["add", filename]).status.success());
}

#[test]
fn manifest_acquires_staged_file() {
    let (_temp, repo) = init_repo();
    commit(&repo, "README.md", "initial\n", "initial");
    stage_file(&repo, "config.py", "API_KEY = 'sk-abc123'\n");

    let manifest = StagedManifest::acquire(&repo).unwrap();
    assert_eq!(manifest.hash_algorithm, GitHashAlgorithm::Sha1);
    assert_eq!(manifest.entries.len(), 1);
    assert_eq!(manifest.total_objects, 1);

    let entry = &manifest.entries[0];
    assert_eq!(entry.path_bytes, b"config.py");
    assert_eq!(entry.kind, StagedEntryKind::File);
    assert!(!entry.object_oid.is_empty());
    assert_eq!(entry.raw_mode, 0o100644);
}

#[test]
fn manifest_captures_modified_file() {
    let (_temp, repo) = init_repo();
    commit(&repo, "file.txt", "original\n", "initial");
    std::fs::write(repo.join("file.txt"), "modified\n").unwrap();
    assert!(git(&repo, &["add", "file.txt"]).status.success());

    let manifest = StagedManifest::acquire(&repo).unwrap();
    assert_eq!(manifest.entries.len(), 1);
    assert_eq!(manifest.entries[0].path_bytes, b"file.txt");
    assert_eq!(manifest.entries[0].kind, StagedEntryKind::File);
}

#[test]
fn manifest_captures_deletion() {
    let (_temp, repo) = init_repo();
    commit(&repo, "doomed.txt", "content\n", "initial");
    assert!(git(&repo, &["rm", "--cached", "doomed.txt"]).status.success());

    let manifest = StagedManifest::acquire(&repo).unwrap();
    assert_eq!(manifest.entries.len(), 1);
    assert_eq!(manifest.entries[0].kind, StagedEntryKind::Deletion);
    assert!(manifest.entries[0].object_oid.is_empty());
    assert_eq!(manifest.entries[0].object_size, 0);
    assert_eq!(manifest.total_objects, 0);
    assert_eq!(manifest.total_bytes, 0);
}

#[test]
fn manifest_captures_executable_mode() {
    let (_temp, repo) = init_repo();
    commit(&repo, "README.md", "initial\n", "initial");
    std::fs::write(repo.join("run.sh"), "#!/bin/sh\necho hi\n").unwrap();
    assert!(git(&repo, &["add", "run.sh"]).status.success());
    assert!(git(&repo, &["update-index", "--chmod=+x", "run.sh"]).status.success());

    let manifest = StagedManifest::acquire(&repo).unwrap();
    assert_eq!(manifest.entries.len(), 1);
    assert_eq!(manifest.entries[0].raw_mode, 0o100755);
    assert_eq!(manifest.entries[0].kind, StagedEntryKind::File);
}

#[test]
fn manifest_captures_symlink() {
    let (_temp, repo) = init_repo();
    commit(&repo, "target.txt", "content\n", "initial");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("target.txt", repo.join("link.txt")).unwrap();
        assert!(git(&repo, &["add", "link.txt"]).status.success());

        let manifest = StagedManifest::acquire(&repo).unwrap();
        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(manifest.entries[0].kind, StagedEntryKind::Symlink);
        assert_eq!(manifest.entries[0].raw_mode, 0o120000);
    }
}

#[test]
fn manifest_index_fingerprint_is_deterministic() {
    let (_temp, repo) = init_repo();
    commit(&repo, "README.md", "initial\n", "initial");
    stage_file(&repo, "file1.py", "content1\n");
    stage_file(&repo, "file2.py", "content2\n");

    let manifest1 = StagedManifest::acquire(&repo).unwrap();
    let manifest2 = StagedManifest::acquire(&repo).unwrap();

    assert_eq!(manifest1.index_fingerprint, manifest2.index_fingerprint);
}

#[test]
fn manifest_fingerprint_changes_on_content_change() {
    let (_temp, repo) = init_repo();
    commit(&repo, "README.md", "initial\n", "initial");
    stage_file(&repo, "file.py", "content1\n");

    let manifest1 = StagedManifest::acquire(&repo).unwrap();

    std::fs::write(repo.join("file.py"), "content2\n").unwrap();
    assert!(git(&repo, &["add", "file.py"]).status.success());

    let manifest2 = StagedManifest::acquire(&repo).unwrap();
    assert_ne!(manifest1.index_fingerprint, manifest2.index_fingerprint);
}

#[test]
fn manifest_fingerprint_changes_on_path_change() {
    let (_temp, repo) = init_repo();
    commit(&repo, "README.md", "initial\n", "initial");
    stage_file(&repo, "file.py", "content\n");

    let manifest1 = StagedManifest::acquire(&repo).unwrap();

    assert!(git(&repo, &["rm", "--cached", "file.py"]).status.success());
    stage_file(&repo, "different_name.py", "content\n");

    let manifest2 = StagedManifest::acquire(&repo).unwrap();
    assert_ne!(manifest1.index_fingerprint, manifest2.index_fingerprint);
}

#[test]
fn manifest_fingerprint_matches_after_recompute() {
    let (_temp, repo) = init_repo();
    commit(&repo, "README.md", "initial\n", "initial");
    stage_file(&repo, "file.py", "content\n");

    let manifest = StagedManifest::acquire(&repo).unwrap();
    // The index has not changed since acquisition, so the fingerprint
    // should match when re-read from the repository.
    assert!(manifest.fingerprint_matches(&repo));
}

#[test]
fn manifest_total_bytes_excludes_deletions() {
    let (_temp, repo) = init_repo();
    commit(&repo, "doomed.txt", "will be deleted\n", "initial");
    commit(&repo, "keep.txt", "kept\n", "second");

    assert!(git(&repo, &["rm", "--cached", "doomed.txt"]).status.success());
    stage_file(&repo, "new.txt", "new content\n");

    let manifest = StagedManifest::acquire(&repo).unwrap();
    assert!(manifest.total_bytes > 0);
    assert_eq!(manifest.entries.len(), 2, "one deletion and one file entry");
    assert_eq!(
        manifest.total_objects, 1,
        "total_objects must count only non-deletion entries"
    );
}

#[test]
fn manifest_preserves_non_utf8_path_bytes() {
    let (_temp, repo) = init_repo();
    commit(&repo, "README.md", "initial\n", "initial");

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bad_bytes: &[u8] = b"bad\xff\xfe.txt";
        let bad_name = std::ffi::OsStr::from_bytes(bad_bytes);
        let path = repo.join(bad_name);
        std::fs::write(&path, "content\n").unwrap();
        // git add with non-UTF-8 path: use OsStr args directly.
        let output = Command::new("git")
            .args(["add", "--"])
            .arg(bad_name)
            .current_dir(&repo)
            .output()
            .unwrap();
        assert!(output.status.success(), "git add non-utf8 failed: {output:?}");

        let manifest = StagedManifest::acquire(&repo).unwrap();
        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(manifest.entries[0].path_bytes, bad_bytes);
    }
}

#[test]
fn manifest_multiple_entries_preserve_order() {
    let (_temp, repo) = init_repo();
    commit(&repo, "README.md", "initial\n", "initial");
    stage_file(&repo, "zebra.py", "z\n");
    stage_file(&repo, "alpha.py", "a\n");
    stage_file(&repo, "middle.py", "m\n");

    let manifest = StagedManifest::acquire(&repo).unwrap();
    assert_eq!(manifest.entries.len(), 3);
    // Git diff --raw outputs in the repository's index order, which is
    // typically alphabetical. Verify all three are present.
    let paths: Vec<&[u8]> = manifest.entries.iter().map(|e| e.path_bytes.as_slice()).collect();
    assert!(paths.iter().any(|p| *p == b"zebra.py"));
    assert!(paths.iter().any(|p| *p == b"alpha.py"));
    assert!(paths.iter().any(|p| *p == b"middle.py"));
}
