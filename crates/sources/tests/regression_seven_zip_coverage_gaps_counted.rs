//! 7z archives that cannot be read must emit a source error and increment skip
//! counters.

#[path = "support/archive.rs"]
mod archive_support;

mod support;

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{FilesystemSource, skip_counts};
use support::split_chunk_results;

#[test]
fn corrupt_seven_zip_counts_as_unreadable() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("broken.7z"), b"not a seven zip archive")
        .expect("write corrupt 7z");

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();

    assert_eq!(
        rows.len(),
        1,
        "corrupt 7z should emit one visible source error"
    );
    let err = rows[0]
        .as_ref()
        .expect_err("corrupt 7z must be an error row");
    assert!(
        err.to_string().contains("cannot open archive")
            && err.to_string().contains("archive was not scanned"),
        "error should name the unscanned 7z archive, got {err}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "corrupt 7z coverage gap must be counted as unreadable"
    );
}

#[test]
fn seven_zip_archive_truncation_surfaces_source_error() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    const MAX_FILE_SIZE: u64 = 16 * 1024;
    let dir = tempfile::tempdir().expect("tempdir");
    let payload = vec![b'A'; MAX_FILE_SIZE as usize];
    let entries: Vec<(String, Vec<u8>)> = (0..5)
        .map(|index| (format!("entry-{index}.txt"), payload.clone()))
        .collect();
    let entry_refs: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    let archive_bytes = archive_support::build_seven_zip(&entry_refs);
    assert!(
        archive_bytes.len() <= MAX_FILE_SIZE as usize,
        "fixture must stay under the outer file cap so the 7z extractor reaches the inner archive budget; archive bytes={}",
        archive_bytes.len()
    );
    std::fs::write(dir.path().join("bomb.7z"), archive_bytes).expect("write 7z bomb fixture");

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .with_max_file_size(MAX_FILE_SIZE)
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        (1..5).contains(&chunks.len()),
        "7z truncation should keep admitted entry chunks but stop before scanning every entry; chunks={chunks:?}"
    );
    assert_eq!(
        errors.len(),
        1,
        "7z archive truncation must surface one source error row"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("archive extraction") && err.contains("remaining entries were not scanned"),
        "error should describe partial 7z coverage, got {err}"
    );
    assert_eq!(
        skip_counts().archive_truncated,
        1,
        "7z archive-budget truncation must bump ARCHIVE_TRUNCATED exactly once"
    );
}

#[test]
fn seven_zip_entry_read_errors_are_per_entry_skips() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/filesystem/extract/seven_zip.rs"
    ))
    .expect("7z extractor source must be readable");

    assert!(
        source.contains("\"cannot read 7z entry; skipping\""),
        "7z entry read errors must be operator-visible per-entry skips"
    );
    assert!(
        source.contains("failed to scan 7z entry"),
        "7z entry read errors must also emit machine-visible source errors"
    );
    assert!(
        source.contains("return Ok(true);"),
        "7z entry read errors must continue to the next archive entry"
    );
    assert!(
        !source.contains("read_to_end(&mut content)?"),
        "7z entry body reads must not abort the whole archive through ?"
    );
    assert!(
        !source.contains("drain_entry(entry_reader)?"),
        "7z skipped-entry draining must not abort the whole archive through ?"
    );
}
