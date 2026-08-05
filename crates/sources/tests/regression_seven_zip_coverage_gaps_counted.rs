//! 7z archives that cannot be read must emit a source error and increment skip
//! counters.

#[path = "support/archive.rs"]
mod archive_support;

mod support;

use keyhog_core::Source;
use keyhog_sources::testing::{TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};
use sevenz_rust2::{ArchiveEntry, ArchiveWriter, SourceReader};
use std::io::Cursor;
use support::split_chunk_results;

#[cfg(unix)]
fn lock_exclusive(path: &std::path::Path) -> std::fs::File {
    use std::os::unix::io::AsRawFd;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open lock target");
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(rc, 0, "exclusive lock acquired for test fixture");
    file
}

fn write_seven_zip_with_special_entries(root: &std::path::Path) -> std::path::PathBuf {
    let archive_path = root.join("special.7z");
    let cursor = Cursor::new(Vec::new());
    let mut writer = ArchiveWriter::new(cursor).expect("create 7z writer");
    writer.set_encrypt_header(false);

    let mut streamed_link = ArchiveEntry::new_file("link.env");
    streamed_link.has_windows_attributes = true;
    streamed_link.windows_attributes = 0o120777_u32 << 16;
    writer
        .push_archive_entry(streamed_link, Some(Cursor::new(&b"target.env"[..])))
        .expect("push streamed symlink entry");

    let mut metadata_link = ArchiveEntry::new_file("metadata-link.env");
    metadata_link.has_windows_attributes = true;
    metadata_link.windows_attributes = 0o120777_u32 << 16;
    writer
        .push_archive_entry::<Cursor<&[u8]>>(metadata_link, None)
        .expect("push metadata symlink entry");

    let safe = ArchiveEntry::new_file("safe.env");
    writer
        .push_archive_entry(safe, Some(Cursor::new(&b"SAFE=AKIAVKODRH4GCR7HOKMA\n"[..])))
        .expect("push safe entry");

    let archive_bytes = writer.finish().expect("finish 7z").into_inner();
    std::fs::write(&archive_path, archive_bytes).expect("write 7z archive");
    archive_path
}

fn write_solid_seven_zip_with_special_then_safe(root: &std::path::Path) -> std::path::PathBuf {
    let archive_path = root.join("solid-special.7z");
    let cursor = Cursor::new(Vec::new());
    let mut writer = ArchiveWriter::new(cursor).expect("create solid 7z writer");
    writer.set_encrypt_header(false);

    let mut streamed_link = ArchiveEntry::new_file("solid-link.env");
    streamed_link.has_windows_attributes = true;
    streamed_link.windows_attributes = 0o120777_u32 << 16;
    let safe = ArchiveEntry::new_file("solid-safe.env");

    writer
        .push_archive_entries(
            vec![streamed_link, safe],
            vec![
                SourceReader::new(Cursor::new(&b"solid-target.env"[..])),
                SourceReader::new(Cursor::new(&b"SAFE=AKIA44WYPVTKMUY7OFCA\n"[..])),
            ],
        )
        .expect("push solid entries");

    let archive_bytes = writer.finish().expect("finish solid 7z").into_inner();
    std::fs::write(&archive_path, archive_bytes).expect("write solid 7z archive");
    archive_path
}

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

#[cfg(unix)]
#[test]
fn locked_seven_zip_emits_source_error() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let archive_path = dir.path().join("locked.7z");
    std::fs::write(&archive_path, b"locked bytes should not be parsed").expect("write 7z");
    let _lock = lock_exclusive(&archive_path);

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        chunks.is_empty(),
        "locked 7z input must not produce clean chunks; chunks={chunks:?}"
    );
    assert_eq!(
        errors.len(),
        1,
        "locked 7z input must emit one SourceError row"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("failed to scan 7z archive")
            && error.contains("locked.7z")
            && error.contains("compressed input")
            && error.contains("archive was not scanned"),
        "locked 7z SourceError must name the unscanned archive, got {error:?}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "locked 7z input must count as unreadable"
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
fn seven_zip_special_entries_emit_source_errors_and_keep_safe_sibling() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let _archive = write_seven_zip_with_special_entries(dir.path());

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let bodies: Vec<_> = chunks
        .iter()
        .map(|chunk| chunk.data.as_str().to_owned())
        .collect();

    assert!(
        bodies
            .iter()
            .any(|body| body.contains("AKIAVKODRH4GCR7HOKMA")),
        "safe 7z sibling must still be scanned; bodies={bodies:?}"
    );
    assert!(
        !bodies.iter().any(|body| body.contains("target.env")),
        "7z symlink payload must not be scanned as file content; bodies={bodies:?}"
    );
    assert_eq!(
        errors.len(),
        2,
        "streamed and no-stream 7z special entries must both emit SourceError rows"
    );
    let rendered_errors: Vec<_> = errors.iter().map(ToString::to_string).collect();
    assert!(
        rendered_errors.iter().any(|error| {
            error.contains("special.7z//link.env") && error.contains("special file type")
        }) && rendered_errors.iter().any(|error| {
            error.contains("special.7z//metadata-link.env") && error.contains("special file type")
        }),
        "7z special-entry errors must name every skipped special entry, got {rendered_errors:?}"
    );
    assert_eq!(
        skip_counts().unreadable,
        2,
        "each 7z special entry must count as an unreadable coverage gap"
    );
}

#[test]
fn solid_seven_zip_special_entry_drains_before_safe_sibling() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let _archive = write_solid_seven_zip_with_special_then_safe(dir.path());

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let bodies: Vec<_> = chunks
        .iter()
        .map(|chunk| chunk.data.as_str().to_owned())
        .collect();

    assert!(
        bodies
            .iter()
            .any(|body| body.contains("AKIA44WYPVTKMUY7OFCA")),
        "safe solid 7z sibling must scan after draining the refused special entry; bodies={bodies:?}"
    );
    assert!(
        !bodies.iter().any(|body| body.contains("solid-target.env")),
        "solid 7z symlink payload must not be scanned as file content; bodies={bodies:?}"
    );
    assert_eq!(
        errors.len(),
        1,
        "solid 7z special entry must emit one SourceError row"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("solid-special.7z//solid-link.env") && error.contains("special file type"),
        "solid 7z special-entry error must name the refused entry, got {error}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "the refused solid 7z special entry must count as unreadable"
    );
}

