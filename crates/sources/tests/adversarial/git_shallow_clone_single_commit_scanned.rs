//! Shallow git clone (depth 1) must still scan without panic, AND must never
//! read as a clean scan when the graft boundary hides real history.
//!
//! The second half is a recall contract, not a robustness one. `--git-history`
//! and `--git-blobs` exist to recover a credential that was committed and later
//! removed. In a depth-1 clone that credential is not in the object database at
//! all, so both sources used to exit 0 with `scan_status: success` and an empty
//! coverage-gap summary while a full clone of the same repository reported it.
//! That is a structured false clean. The gap is now counted as the absent
//! parent commits the boundary names.

use crate::support::split_chunk_results;
#[cfg(feature = "git")]
#[test]
fn git_shallow_clone_single_commit_scanned() {
    use keyhog_core::Source;
    use keyhog_sources::{GitHistorySource, GitSource};
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

    let history_rows: Vec<_> = GitHistorySource::new(shallow.path().to_path_buf())
        .chunks()
        .collect();
    let (history_chunks, history_errors) = split_chunk_results(&history_rows);
    assert!(
        history_errors.is_empty(),
        "depth-one history must scan its available HEAD commit: {history_errors:?}"
    );
    assert!(
        history_chunks.iter().any(|chunk| {
            chunk.data.contains("SHALLOW=AKIA")
                && chunk.metadata.source_type.as_ref() == "git-history"
                && chunk.metadata.commit.is_some()
        }),
        "depth-one history must expose the HEAD added line with commit identity: {history_chunks:?}"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_shallow_clone_single_commit_scanned() {}

/// Origin with two commits: the first adds a credential, the second removes it.
/// A depth-1 clone therefore contains NONE of the credential's bytes.
#[cfg(feature = "git")]
fn origin_with_removed_credential() -> tempfile::TempDir {
    use std::process::Command;

    let origin = tempfile::tempdir().expect("origin");
    let git = |args: &[&str]| {
        assert!(
            Command::new("git")
                .args([
                    "-c",
                    "user.email=test@example.com",
                    "-c",
                    "user.name=test",
                    "-c",
                    "commit.gpgsign=false",
                ])
                .args(args)
                .current_dir(origin.path())
                .status()
                .expect("git")
                .success(),
            "git {args:?}"
        );
    };
    git(&["init", "-b", "main", "."]);
    std::fs::write(
        origin.path().join("removed.env"),
        "DELETED=AKIAQYLPMN5HFIQR7XYA\n",
    )
    .expect("write");
    git(&["add", "-A"]);
    git(&["commit", "-m", "add credential"]);
    std::fs::remove_file(origin.path().join("removed.env")).expect("remove");
    std::fs::write(origin.path().join("README.md"), "clean\n").expect("write readme");
    git(&["add", "-A"]);
    git(&["commit", "-m", "remove credential"]);
    origin
}

#[cfg(feature = "git")]
fn clone_at_depth(origin: &std::path::Path, depth: Option<u32>) -> tempfile::TempDir {
    use std::process::Command;

    let clone = tempfile::tempdir().expect("clone");
    let url = format!("file://{}", origin.display());
    let mut command = Command::new("git");
    command.arg("clone");
    if let Some(depth) = depth {
        command.args(["--depth", &depth.to_string()]);
    }
    assert!(
        command
            .args([&url, "."])
            .current_dir(clone.path())
            .status()
            .expect("git clone")
            .success(),
        "git clone depth={depth:?}"
    );
    clone
}

/// The fixture the fix exists for: the credential is reachable only from the
/// commit the shallow boundary cut away. A full clone finds it; the depth-1
/// clone cannot, and MUST say so instead of reporting a clean history.
#[cfg(feature = "git")]
#[test]
fn shallow_clone_hiding_a_deleted_credential_counts_a_coverage_gap() {
    use keyhog_core::Source;
    use keyhog_sources::testing::{TestApi};
    use keyhog_sources::{skip_counts, GitHistorySource, GitSource};

    let _guard = TestApi.skip_counter_guard();
    let origin = origin_with_removed_credential();

    // Control: the full clone recovers the deleted credential with no gap.
    TestApi.reset_skip_counters();
    let full = clone_at_depth(origin.path(), None);
    let full_rows: Vec<_> = GitSource::new(full.path().to_path_buf()).chunks().collect();
    let (full_chunks, _full_errors) = split_chunk_results(&full_rows);
    assert!(
        full_chunks
            .iter()
            .any(|chunk| chunk.data.contains("DELETED=AKIAQYLPMN5HFIQR7XYA")),
        "full clone must recover the deleted credential; got {full_chunks:?}"
    );
    assert_eq!(
        skip_counts().git_object_unreadable,
        0,
        "a complete history must report no unscanned-object gap"
    );

    let shallow = clone_at_depth(origin.path(), Some(1));
    let assert_gap = |label: &str, rows: &[Result<keyhog_core::Chunk, keyhog_core::SourceError>]| {
        let (chunks, _errors) = split_chunk_results(rows);
        assert!(
            !chunks
                .iter()
                .any(|chunk| chunk.data.contains("DELETED=AKIAQYLPMN5HFIQR7XYA")),
            "{label}: the depth-1 clone cannot contain the credential's bytes; got {chunks:?}"
        );
        assert_eq!(
            skip_counts().git_object_unreadable,
            1,
            "{label}: the one parent commit the graft boundary names is absent, so exactly one \
             unscanned Git object must be counted; a zero here is the false clean this test \
             exists to forbid"
        );
    };

    TestApi.reset_skip_counters();
    let blob_rows: Vec<_> = GitSource::new(shallow.path().to_path_buf())
        .chunks()
        .collect();
    assert_gap("git-blobs", &blob_rows);

    TestApi.reset_skip_counters();
    let history_rows: Vec<_> = GitHistorySource::new(shallow.path().to_path_buf())
        .chunks()
        .collect();
    assert_gap("git-history", &history_rows);
}

/// A depth-1 clone of a SINGLE-commit repository still writes a `shallow` file,
/// but its one boundary entry is the root commit, which names no parents and
/// hides nothing. Counting boundary commits would invent a gap here; counting
/// absent parents does not.
#[cfg(feature = "git")]
#[test]
fn shallow_clone_whose_boundary_is_the_root_commit_reports_no_gap() {
    use keyhog_core::Source;
    use keyhog_sources::testing::{TestApi};
    use keyhog_sources::{skip_counts, GitSource};
    use std::process::Command;

    let _guard = TestApi.skip_counter_guard();
    let origin = tempfile::tempdir().expect("origin");
    let git = |args: &[&str]| {
        assert!(
            Command::new("git")
                .args([
                    "-c",
                    "user.email=test@example.com",
                    "-c",
                    "user.name=test",
                    "-c",
                    "commit.gpgsign=false",
                ])
                .args(args)
                .current_dir(origin.path())
                .status()
                .expect("git")
                .success(),
            "git {args:?}"
        );
    };
    git(&["init", "-b", "main", "."]);
    std::fs::write(origin.path().join("only.env"), "ONLY=AKIAQYLPMN5HFIQR7XYA\n").expect("write");
    git(&["add", "-A"]);
    git(&["commit", "-m", "only commit"]);

    let shallow = clone_at_depth(origin.path(), Some(1));
    assert!(
        shallow.path().join(".git/shallow").exists(),
        "git writes a shallow file even when the boundary is the root commit"
    );

    TestApi.reset_skip_counters();
    let rows: Vec<_> = GitSource::new(shallow.path().to_path_buf())
        .chunks()
        .collect();
    let (chunks, _errors) = split_chunk_results(&rows);
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("ONLY=AKIAQYLPMN5HFIQR7XYA")),
        "the only commit is present and must be scanned; got {chunks:?}"
    );
    assert_eq!(
        skip_counts().git_object_unreadable,
        0,
        "a root-commit boundary hides no ancestor, so it must not fabricate a coverage gap"
    );
}
