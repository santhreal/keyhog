//! RAR archives that cannot be read must emit a source error and increment skip
//! counters.

mod support;

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};
use rars::{rar15_40, rar50, ArchiveVersion, FeatureSet};
use support::split_chunk_results;

const UNIX_SYMLINK_MODE: u64 = 0o120777;
const UNIX_REGULAR_MODE: u64 = 0o100644;
const RAR15_40_UNIX_HOST_OS: u64 = 3;
const RAR50_UNIX_HOST_OS: u64 = 1;

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

#[test]
fn corrupt_rar_counts_as_unreadable() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("broken.rar"), b"not a rar archive").expect("write corrupt RAR");

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();

    assert_eq!(
        rows.len(),
        1,
        "corrupt RAR should emit one visible source error"
    );
    let err = rows[0]
        .as_ref()
        .expect_err("corrupt RAR must be an error row");
    assert!(
        err.to_string().contains("cannot open archive")
            && err.to_string().contains("archive was not scanned"),
        "error should name the unscanned RAR archive, got {err}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "corrupt RAR coverage gap must be counted as unreadable"
    );
}

#[cfg(unix)]
#[test]
fn locked_rar_emits_source_error() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let archive_path = dir.path().join("locked.rar");
    std::fs::write(&archive_path, b"locked bytes should not be parsed").expect("write rar");
    let _lock = lock_exclusive(&archive_path);

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();

    assert_eq!(
        rows.len(),
        1,
        "locked RAR input must emit one visible source error"
    );
    let err = rows[0]
        .as_ref()
        .expect_err("locked RAR input must be an error row");
    assert!(
        err.to_string().contains("failed to scan RAR archive")
            && err.to_string().contains("locked.rar")
            && err.to_string().contains("compressed input")
            && err.to_string().contains("archive was not scanned"),
        "error should name the locked RAR coverage gap, got {err}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "locked RAR coverage gap must be counted as unreadable"
    );
}

#[test]
fn rar15_40_unix_special_entry_emits_source_error_and_keeps_safe_sibling() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let archive_path = dir.path().join("rar29-special.rar");
    let archive = rar15_40::write_stored_archive(
        &[
            rar15_40::StoredEntry {
                name: b"link.env",
                data: b"SHOULD_NOT_SCAN=rar29_link_payload\n",
                file_time: 0,
                file_attr: (UNIX_SYMLINK_MODE as u32) << 16,
                host_os: RAR15_40_UNIX_HOST_OS as u8,
                password: None,
                file_comment: None,
            },
            rar15_40::StoredEntry {
                name: b"safe.env",
                data: b"SAFE_RAR29_SECRET=visible\n",
                file_time: 0,
                file_attr: (UNIX_REGULAR_MODE as u32) << 16,
                host_os: RAR15_40_UNIX_HOST_OS as u8,
                password: None,
                file_comment: None,
            },
        ],
        rar15_40::WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
    )
    .expect("write rar29 fixture");
    std::fs::write(&archive_path, archive).expect("write rar29 archive");

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let bodies: Vec<_> = chunks
        .iter()
        .map(|chunk| chunk.data.as_str().to_owned())
        .collect();
    let rendered_errors: Vec<_> = errors.iter().map(|error| error.to_string()).collect();

    assert!(
        bodies.iter().any(|body| body.contains("SAFE_RAR29_SECRET")),
        "safe RAR29 sibling must still scan; bodies={bodies:?}"
    );
    assert!(
        !bodies.iter().any(|body| body.contains("SHOULD_NOT_SCAN")),
        "RAR29 symlink payload must not be scanned as regular content; bodies={bodies:?}"
    );
    assert_eq!(
        errors.len(),
        1,
        "RAR29 special entry must emit one SourceError row"
    );
    assert!(
        rendered_errors.iter().any(|error| {
            error.contains("rar29-special.rar//link.env") && error.contains("special file type")
        }),
        "RAR29 special-entry error must name the refused entry, got {rendered_errors:?}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "the refused RAR29 special entry must count as unreadable"
    );
}

#[test]
fn rar50_unix_special_entry_emits_source_error_and_keeps_safe_sibling() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let archive_path = dir.path().join("rar50-special.rar");
    let archive = rar50::Rar50Writer::new(rar50::WriterOptions::new(
        ArchiveVersion::Rar50,
        FeatureSet::store_only(),
    ))
    .stored_entries(&[
        rar50::StoredEntry {
            name: b"link.env",
            data: b"SHOULD_NOT_SCAN=rar50_link_payload\n",
            mtime: None,
            attributes: UNIX_SYMLINK_MODE,
            host_os: RAR50_UNIX_HOST_OS,
        },
        rar50::StoredEntry {
            name: b"safe.env",
            data: b"SAFE_RAR50_SECRET=visible\n",
            mtime: None,
            attributes: UNIX_REGULAR_MODE,
            host_os: RAR50_UNIX_HOST_OS,
        },
    ])
    .finish()
    .expect("write rar50 fixture");
    std::fs::write(&archive_path, archive).expect("write rar50 archive");

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let bodies: Vec<_> = chunks
        .iter()
        .map(|chunk| chunk.data.as_str().to_owned())
        .collect();
    let rendered_errors: Vec<_> = errors.iter().map(|error| error.to_string()).collect();

    assert!(
        bodies.iter().any(|body| body.contains("SAFE_RAR50_SECRET")),
        "safe RAR50 sibling must still scan; bodies={bodies:?}"
    );
    assert!(
        !bodies.iter().any(|body| body.contains("SHOULD_NOT_SCAN")),
        "RAR50 symlink payload must not be scanned as regular content; bodies={bodies:?}"
    );
    assert_eq!(
        errors.len(),
        1,
        "RAR50 special entry must emit one SourceError row"
    );
    assert!(
        rendered_errors.iter().any(|error| {
            error.contains("rar50-special.rar//link.env") && error.contains("special file type")
        }),
        "RAR50 special-entry error must name the refused entry, got {rendered_errors:?}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "the refused RAR50 special entry must count as unreadable"
    );
}

#[test]
fn rar15_40_solid_archive_scans_every_regular_member() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let archive_path = dir.path().join("rar29-solid.rar");
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let archive = rar15_40::write_compressed_archive(
        &[
            rar15_40::FileEntry {
                name: b"one.env",
                data: b"RAR29_SOLID_ONE=visible\n",
                file_time: 0,
                file_attr: UNIX_REGULAR_MODE as u32,
                host_os: RAR15_40_UNIX_HOST_OS as u8,
                password: None,
                file_comment: None,
            },
            rar15_40::FileEntry {
                name: b"two.env",
                data: b"RAR29_SOLID_TWO=visible\n",
                file_time: 0,
                file_attr: UNIX_REGULAR_MODE as u32,
                host_os: RAR15_40_UNIX_HOST_OS as u8,
                password: None,
                file_comment: None,
            },
        ],
        rar15_40::WriterOptions::new(ArchiveVersion::Rar29, features),
    )
    .expect("write solid rar29 fixture");
    std::fs::write(&archive_path, archive).expect("write solid rar29 archive");

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let bodies: Vec<_> = chunks
        .iter()
        .map(|chunk| chunk.data.as_str().to_owned())
        .collect();

    assert!(
        errors.is_empty(),
        "solid RAR29 regular members must not emit errors; errors={errors:?}"
    );
    assert!(
        bodies.iter().any(|body| body.contains("RAR29_SOLID_ONE"))
            && bodies.iter().any(|body| body.contains("RAR29_SOLID_TWO")),
        "solid RAR29 must scan every regular member; bodies={bodies:?}"
    );
}

#[test]
fn rar15_40_solid_special_entry_drains_before_safe_sibling() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let archive_path = dir.path().join("rar29-solid-special.rar");
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let refused = b"SHOULD_NOT_SCAN_RAR29_SOLID_SPECIAL=hidden\n".repeat(16);
    let safe = b"SAFE_RAR29_SOLID_AFTER_SPECIAL=visible\n".repeat(8);
    let archive = rar15_40::write_compressed_archive(
        &[
            rar15_40::FileEntry {
                name: b"link.env",
                data: &refused,
                file_time: 0,
                file_attr: UNIX_SYMLINK_MODE as u32,
                host_os: RAR15_40_UNIX_HOST_OS as u8,
                password: None,
                file_comment: None,
            },
            rar15_40::FileEntry {
                name: b"safe.env",
                data: &safe,
                file_time: 0,
                file_attr: UNIX_REGULAR_MODE as u32,
                host_os: RAR15_40_UNIX_HOST_OS as u8,
                password: None,
                file_comment: None,
            },
        ],
        rar15_40::WriterOptions::new(ArchiveVersion::Rar29, features),
    )
    .expect("write mixed solid rar29 fixture");
    std::fs::write(&archive_path, archive).expect("write mixed solid rar29 archive");

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let bodies: Vec<_> = chunks
        .iter()
        .map(|chunk| chunk.data.as_str().to_owned())
        .collect();
    let rendered_errors: Vec<_> = errors.iter().map(|error| error.to_string()).collect();

    assert!(
        bodies
            .iter()
            .any(|body| body.contains("SAFE_RAR29_SOLID_AFTER_SPECIAL")),
        "safe RAR29 solid sibling after refused entry must still scan; bodies={bodies:?}; errors={rendered_errors:?}"
    );
    assert!(
        !bodies
            .iter()
            .any(|body| body.contains("SHOULD_NOT_SCAN_RAR29_SOLID_SPECIAL")),
        "refused RAR29 solid symlink payload must not be scanned; bodies={bodies:?}"
    );
    assert_eq!(
        errors.len(),
        1,
        "RAR29 solid special entry must emit exactly one visible SourceError"
    );
    assert!(
        rendered_errors.iter().any(|error| {
            error.contains("rar29-solid-special.rar//link.env")
                && error.contains("special file type")
        }),
        "RAR29 solid special-entry error must name the refused entry, got {rendered_errors:?}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "the refused RAR29 solid special entry must count as unreadable"
    );
}

#[test]
fn rar50_solid_archive_scans_every_regular_member() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let archive_path = dir.path().join("rar50-solid.rar");
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let first = b"RAR50_SOLID_ONE=visible\n".repeat(16);
    let second = b"RAR50_SOLID_TWO=visible\n".repeat(8);
    let archive =
        rar50::Rar50Writer::new(rar50::WriterOptions::new(ArchiveVersion::Rar50, features))
            .compressed_entries(&[
                rar50::CompressedEntry {
                    name: b"one.env",
                    data: &first,
                    mtime: Some(0),
                    attributes: UNIX_REGULAR_MODE,
                    host_os: RAR50_UNIX_HOST_OS,
                },
                rar50::CompressedEntry {
                    name: b"two.env",
                    data: &second,
                    mtime: Some(0),
                    attributes: UNIX_REGULAR_MODE,
                    host_os: RAR50_UNIX_HOST_OS,
                },
            ])
            .finish()
            .expect("write solid rar50 fixture");
    std::fs::write(&archive_path, archive).expect("write solid rar50 archive");

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let bodies: Vec<_> = chunks
        .iter()
        .map(|chunk| chunk.data.as_str().to_owned())
        .collect();

    assert!(
        errors.is_empty(),
        "solid RAR50 regular members must not emit errors; errors={errors:?}"
    );
    assert!(
        bodies.iter().any(|body| body.contains("RAR50_SOLID_ONE"))
            && bodies.iter().any(|body| body.contains("RAR50_SOLID_TWO")),
        "solid RAR50 must scan every regular member; bodies={bodies:?}"
    );
}

#[test]
fn rar50_solid_special_entry_drains_before_safe_sibling() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let archive_path = dir.path().join("rar50-solid-special.rar");
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let refused = b"SHOULD_NOT_SCAN_RAR50_SOLID_SPECIAL=hidden\n".repeat(16);
    let safe = b"SAFE_RAR50_SOLID_AFTER_SPECIAL=visible\n".repeat(8);
    let archive =
        rar50::Rar50Writer::new(rar50::WriterOptions::new(ArchiveVersion::Rar50, features))
            .compressed_entries(&[
                rar50::CompressedEntry {
                    name: b"link.env",
                    data: &refused,
                    mtime: Some(0),
                    attributes: UNIX_SYMLINK_MODE,
                    host_os: RAR50_UNIX_HOST_OS,
                },
                rar50::CompressedEntry {
                    name: b"safe.env",
                    data: &safe,
                    mtime: Some(0),
                    attributes: UNIX_REGULAR_MODE,
                    host_os: RAR50_UNIX_HOST_OS,
                },
            ])
            .finish()
            .expect("write mixed solid rar50 fixture");
    std::fs::write(&archive_path, archive).expect("write mixed solid rar50 archive");

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let bodies: Vec<_> = chunks
        .iter()
        .map(|chunk| chunk.data.as_str().to_owned())
        .collect();
    let rendered_errors: Vec<_> = errors.iter().map(|error| error.to_string()).collect();

    assert!(
        bodies
            .iter()
            .any(|body| body.contains("SAFE_RAR50_SOLID_AFTER_SPECIAL")),
        "safe RAR50 solid sibling after refused entry must still scan; bodies={bodies:?}; errors={rendered_errors:?}"
    );
    assert!(
        !bodies
            .iter()
            .any(|body| body.contains("SHOULD_NOT_SCAN_RAR50_SOLID_SPECIAL")),
        "refused RAR50 solid symlink payload must not be scanned; bodies={bodies:?}"
    );
    assert_eq!(
        errors.len(),
        1,
        "RAR50 solid special entry must emit exactly one visible SourceError"
    );
    assert!(
        rendered_errors.iter().any(|error| {
            error.contains("rar50-solid-special.rar//link.env")
                && error.contains("special file type")
        }),
        "RAR50 solid special-entry error must name the refused entry, got {rendered_errors:?}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "the refused RAR50 solid special entry must count as unreadable"
    );
}
