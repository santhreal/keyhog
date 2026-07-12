//! TAR and 7z archive entries use the shared path-safety validator.

mod support;

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};
use std::sync::Mutex;

static COUNTER_LOCK: Mutex<()> = Mutex::new(());

fn scan_fixture(name: &str, bytes: Vec<u8>) -> (Vec<String>, Vec<String>, Vec<String>) {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(name), bytes).expect("write archive fixture");

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    let (chunks, errors) = support::split_chunk_results(&rows);

    let bodies = chunks.iter().map(|chunk| chunk.data.to_string()).collect();
    let paths = chunks
        .iter()
        .filter_map(|chunk| chunk.metadata.path.as_deref().map(String::from))
        .collect();
    let errors = errors.iter().map(|error| error.to_string()).collect();
    (bodies, paths, errors)
}

#[test]
fn tar_xz_encoded_dotdot_entry_is_counted_unreadable_and_safe_sibling_scans() {
    let _guard = COUNTER_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    TestApi.reset_skip_counters();

    let tar = support::archive::tar_with_entries(&[
        ("%2e%2e/escape.env", b"SLIP=AKIAQYLPMN5HFIQR7XYA\n"),
        ("safe.txt", b"SAFE_TAR_XZ_ENTRY=visible\n"),
    ]);
    let (bodies, paths, errors) = scan_fixture("bundle.tar.xz", support::archive::encode_xz(&tar));

    assert_eq!(
        skip_counts().unreadable,
        1,
        "unsafe tar entry names must be counted as unreadable coverage gaps"
    );
    assert_eq!(
        errors.len(),
        1,
        "unsafe tar entry names must emit one SourceError without aborting safe siblings"
    );
    let error = &errors[0];
    assert!(
        error.contains("bundle.tar.xz//%2e%2e/escape.env")
            && error.contains("path traversal")
            && error.contains("entry was not scanned"),
        "unsafe tar SourceError must name the unscanned entry, got {error:?}"
    );
    assert!(
        bodies
            .iter()
            .any(|body| body.contains("SAFE_TAR_XZ_ENTRY=visible")),
        "safe tar sibling must still scan; bodies={bodies:?}"
    );
    assert!(
        !bodies.iter().any(|body| body.contains("SLIP=AKIA")),
        "unsafe tar entry body must not surface; bodies={bodies:?}"
    );
    assert!(
        paths
            .iter()
            .any(|path| path.ends_with("bundle.tar.xz//safe.txt")),
        "safe tar sibling path must preserve archive metadata; paths={paths:?}"
    );
    assert!(
        !paths.iter().any(|path| path.contains("%2e%2e/escape.env")),
        "unsafe tar entry name must not surface in metadata; paths={paths:?}"
    );
}

#[test]
fn seven_zip_dotdot_entry_is_counted_unreadable_and_safe_sibling_scans() {
    let _guard = COUNTER_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    TestApi.reset_skip_counters();

    let archive = support::archive::build_seven_zip(&[
        ("../escape.env", b"SLIP=AKIAQYLPMN5HFIQR7XYA\n"),
        ("safe.txt", b"SAFE_7Z_ENTRY=visible\n"),
    ]);
    let (bodies, paths, errors) = scan_fixture("bundle.7z", archive);

    assert_eq!(
        skip_counts().unreadable,
        1,
        "unsafe 7z entry names must be counted as unreadable coverage gaps"
    );
    assert_eq!(
        errors.len(),
        1,
        "unsafe 7z entry names must emit one SourceError without aborting safe siblings"
    );
    let error = &errors[0];
    assert!(
        error.contains("bundle.7z//../escape.env")
            && error.contains("path traversal")
            && error.contains("entry was not scanned"),
        "unsafe 7z SourceError must name the unscanned entry, got {error:?}"
    );
    assert!(
        bodies
            .iter()
            .any(|body| body.contains("SAFE_7Z_ENTRY=visible")),
        "safe 7z sibling must still scan; bodies={bodies:?}"
    );
    assert!(
        !bodies.iter().any(|body| body.contains("SLIP=AKIA")),
        "unsafe 7z entry body must not surface; bodies={bodies:?}"
    );
    assert!(
        paths
            .iter()
            .any(|path| path.ends_with("bundle.7z//safe.txt")),
        "safe 7z sibling path must preserve archive metadata; paths={paths:?}"
    );
    assert!(
        !paths.iter().any(|path| path.contains("../escape.env")),
        "unsafe 7z entry name must not surface in metadata; paths={paths:?}"
    );
}

#[test]
fn zip_dotdot_entry_is_counted_unreadable_and_safe_sibling_scans() {
    let _guard = COUNTER_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    TestApi.reset_skip_counters();

    let archive = support::archive::zip_with_entries(&[
        ("../escape.env", b"SLIP=AKIAQYLPMN5HFIQR7XYA\n"),
        ("safe.txt", b"SAFE_ZIP_ENTRY=visible\n"),
    ]);
    let (bodies, paths, errors) = scan_fixture("bundle.zip", archive);

    assert_eq!(
        skip_counts().unreadable,
        1,
        "unsafe ZIP entry names must be counted as unreadable coverage gaps"
    );
    assert_eq!(
        errors.len(),
        1,
        "unsafe ZIP entry names must emit one SourceError without aborting safe siblings"
    );
    let error = &errors[0];
    assert!(
        error.contains("bundle.zip//../escape.env")
            && error.contains("path traversal")
            && error.contains("entry was not scanned"),
        "unsafe ZIP SourceError must name the unscanned entry, got {error:?}"
    );
    assert!(
        bodies
            .iter()
            .any(|body| body.contains("SAFE_ZIP_ENTRY=visible")),
        "safe ZIP sibling must still scan; bodies={bodies:?}"
    );
    assert!(
        !bodies.iter().any(|body| body.contains("SLIP=AKIA")),
        "unsafe ZIP entry body must not surface; bodies={bodies:?}"
    );
    assert!(
        paths
            .iter()
            .any(|path| path.ends_with("bundle.zip//safe.txt")),
        "safe ZIP sibling path must preserve archive metadata; paths={paths:?}"
    );
    assert!(
        !paths.iter().any(|path| path.contains("../escape.env")),
        "unsafe ZIP entry name must not surface in metadata; paths={paths:?}"
    );
}
