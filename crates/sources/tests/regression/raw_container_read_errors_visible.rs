#![cfg(unix)]

use std::os::unix::fs::symlink;

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};

use crate::support::split_chunk_results;

#[test]
fn raw_tar_symlink_refusal_emits_source_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside tempdir");
    let target = outside.path().join("victim.txt");
    std::fs::write(&target, b"target bytes that must not be followed").expect("write target");
    let path = dir.path().join("linked.tar");
    symlink(&target, &path).expect("create tar symlink");

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();

    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        chunks.is_empty(),
        "raw tar symlink must not produce clean chunks from the symlink target"
    );
    assert_eq!(
        errors.len(),
        1,
        "raw tar symlink refusal must emit one machine-visible SourceError"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("failed to scan tar file")
            && error.contains("linked.tar")
            && error.contains("symlink")
            && error.contains("tar file was not scanned"),
        "raw tar symlink refusal must identify the unscanned path, got {error:?}"
    );
    assert!(
        skip_counts().unreadable >= 1,
        "raw tar symlink refusal must also count as unreadable coverage"
    );
}

#[test]
fn walked_container_symlink_refusals_emit_source_errors() {
    for ext in ["har", "zip", "gz", "pdf"] {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside tempdir");
        let target = outside.path().join("victim.txt");
        std::fs::write(
            &target,
            format!("{ext} target bytes that must not be followed"),
        )
        .expect("write target");
        let path = dir.path().join(format!("linked.{ext}"));
        symlink(&target, &path).expect("create container symlink");

        TestApi.reset_skip_counters();
        let source = FilesystemSource::new(dir.path().to_path_buf());
        let rows: Vec<_> = source.chunks().collect();

        let (chunks, errors) = split_chunk_results(&rows);
        assert!(
            chunks.is_empty(),
            ".{ext} symlink must not produce clean chunks from the symlink target"
        );
        assert_eq!(
            errors.len(),
            1,
            ".{ext} symlink refusal must emit one machine-visible SourceError"
        );
        let error = errors[0].to_string();
        assert!(
            error.contains(&format!("linked.{ext}"))
                && (error.contains("archive symlink")
                    || error.contains("failed to scan")
                    || error.contains("was not scanned")),
            ".{ext} symlink refusal must identify the unscanned path, got {error:?}"
        );
        assert!(
            skip_counts().unreadable >= 1,
            ".{ext} symlink refusal must also count as unreadable coverage"
        );
    }
}

#[test]
fn walked_plain_symlink_to_container_target_emits_source_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside tempdir");
    let target = outside.path().join("capture.har");
    std::fs::write(&target, b"target HAR bytes that must not be followed").expect("write target");
    let path = dir.path().join("plain-name.txt");
    symlink(&target, &path).expect("create plain symlink to container target");

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();

    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        chunks.is_empty(),
        "plain symlink to container target must not produce clean target chunks"
    );
    assert_eq!(
        errors.len(),
        1,
        "plain symlink to container target must emit one machine-visible SourceError"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("plain-name.txt") && error.contains("archive symlink"),
        "plain symlink refusal must identify the unscanned path, got {error:?}"
    );
    assert!(
        skip_counts().unreadable >= 1,
        "plain symlink to container target must also count as unreadable coverage"
    );
}
