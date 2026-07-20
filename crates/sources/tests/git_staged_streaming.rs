#![cfg(feature = "git")]

use keyhog_core::Source;
use keyhog_sources::GitStagedSource;
use std::process::Command;

fn git(repo: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("run git")
}

#[test]
fn oversized_staged_header_emits_error_and_preserves_later_records() {
    let input = b"oversized.env\0:later-header";
    let (error, continue_later_records, remainder) =
        keyhog_sources::testing::oversized_staged_header_path_outcome_for_test(input, 1024);
    assert!(
        error.contains("raw diff header exceeded")
            && error.contains("oversized index entry was not scanned"),
        "oversized header must produce an exact recoverable coverage error: {error}"
    );
    assert!(
        continue_later_records,
        "a consumed path leaves the iterator aligned for later staged records"
    );
    assert_eq!(remainder, b":later-header");
}

#[test]
fn oversized_staged_header_without_path_fails_closed() {
    let (error, continue_later_records, remainder) =
        keyhog_sources::testing::oversized_staged_header_path_outcome_for_test(b"", 1024);
    assert!(
        error.contains("ended before the path for an oversized index entry"),
        "missing path must retain the exact truncation cause: {error}"
    );
    assert!(!continue_later_records);
    assert!(remainder.is_empty());
}

#[test]
fn staged_chunks_stream_and_preserve_rows_before_a_later_object_error() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let repo = dir.path();
    assert!(git(repo, &["init", "-q"]).status.success());
    std::fs::write(repo.join("a.env"), "first staged content\n").expect("write a");
    std::fs::write(repo.join("b.env"), "second staged content\n").expect("write b");
    assert!(git(repo, &["add", "a.env", "b.env"]).status.success());

    let b_id = String::from_utf8(git(repo, &["hash-object", "b.env"]).stdout)
        .expect("object id is UTF-8")
        .trim()
        .to_owned();
    let b_object = repo.join(".git/objects").join(&b_id[..2]).join(&b_id[2..]);
    assert!(b_object.is_file(), "fixture must use a loose Git object");

    let source = GitStagedSource::try_new(repo.to_path_buf()).expect("construct staged source");
    let mut chunks = source.chunks();
    let first = chunks
        .next()
        .expect("first staged row")
        .expect("scan a.env");
    assert_eq!(first.metadata.path.as_deref(), Some("a.env"));

    std::fs::remove_file(&b_object).expect("remove later staged object");
    let second = chunks
        .next()
        .expect("missing staged object must produce a visible row")
        .expect_err("missing staged object must fail closed");
    let message = second.to_string();
    assert!(
        message.contains("b.env") && message.contains("unreadable"),
        "later object error must retain its path and cause: {message}"
    );
}
