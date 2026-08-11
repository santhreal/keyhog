use keyhog_core::{Source, SourceError};
use keyhog_sources::testing::TestApi;
use keyhog_sources::FilesystemSource;
use std::num::NonZeroUsize;
use std::path::PathBuf;

#[test]
fn filesystem_source_yields_file_contents() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("secret.env");
    std::fs::write(&file, "TOKEN=abc123\n").unwrap();

    let source = FilesystemSource::new(PathBuf::from(dir.path()));
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
    assert!(!chunks.is_empty());
    assert!(chunks[0].data.contains("TOKEN=abc123"));
}

#[test]
fn filesystem_source_single_file_root_is_not_directory_audit_error() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("single.env");
    std::fs::write(&file, "TOKEN=single_file_root\n").unwrap();

    let source = FilesystemSource::new(file);
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

    assert_eq!(chunks.len(), 1);
    assert!(chunks[0].data.contains("TOKEN=single_file_root"));
}

#[test]
fn filesystem_source_does_not_skip_extensionless_text_with_single_nul() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("nul-bearing-config");
    std::fs::write(&file, b"API_KEY=abc\0def\n").unwrap();

    let source = FilesystemSource::new(PathBuf::from(dir.path()));
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(
        chunks.len(),
        1,
        "an extensionless text file with one embedded NUL must not be pre-skipped as binary"
    );
    assert_eq!(chunks[0].metadata.source_type.as_ref(), "filesystem");
    assert!(
        chunks[0].data.contains("API_KEY=abc\0def"),
        "NUL-bearing text must reach the scanner unchanged; chunk={:?}",
        chunks[0]
    );
}

#[test]
fn filesystem_source_missing_path_yields_source_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist");

    let source = FilesystemSource::new(missing.clone());
    let row = source
        .chunks()
        .next()
        .expect("missing filesystem root must emit a visible SourceError");
    let err = row.expect_err("missing filesystem root must not look like a clean scan");
    let SourceError::Io(error) = err else {
        panic!("missing filesystem root must emit SourceError::Io; got {err:?}");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    let message = error.to_string();
    assert!(
        message.contains("filesystem root") && message.contains("does not exist"),
        "missing root error must explain the unscanned path; got {message:?} for {}",
        missing.display()
    );
}

#[test]
fn filesystem_reader_iterator_panic_surfaces_source_error() {
    let rows = TestApi.reader_panic_rows();
    assert_eq!(rows.len(), 1, "reader panic should emit one ordered error");
    let err = rows[0]
        .as_ref()
        .expect_err("reader panic must not look like clean EOF");
    assert!(
        err.to_string().contains("file-walk iterator panicked")
            && err.to_string().contains("reader exploded")
            && err.to_string().contains("remaining files were not scanned"),
        "unexpected reader panic error: {err}"
    );
}

#[test]
fn filesystem_reader_process_entry_panic_surfaces_source_error() {
    let rows = TestApi.reader_process_entry_panic_rows();
    assert_eq!(
        rows.len(),
        1,
        "entry extraction panic should emit one ordered error"
    );
    let err = rows[0]
        .as_ref()
        .expect_err("entry extraction panic must not look like clean EOF");
    assert!(
        err.to_string().contains("file extraction panicked")
            && err.to_string().contains("panic.zip")
            && err.to_string().contains("extractor exploded")
            && err
                .to_string()
                .contains("remaining content for that entry was not scanned"),
        "unexpected process-entry panic error: {err}"
    );
}

#[test]
fn default_max_file_size_matches_core_scan_config() {
    let max_file_size = TestApi.filesystem_default_max_file_size();
    assert_eq!(max_file_size, keyhog_core::DEFAULT_MAX_FILE_SIZE_BYTES);
    assert_eq!(
        max_file_size,
        keyhog_core::ScanConfig::default().max_file_size
    );
}

#[test]
fn filesystem_reader_default_is_one_direct_producer_for_every_scan_pool() {
    // WHY: production scaling evidence showed no throughput gain from a
    // multi-thread reader crew, while every extra reader retained another
    // in-flight part and required the ordered-reassembly thread. One reader
    // emits directly to the bounded scanner channel. Explicit configuration
    // remains available for measured storage workloads.
    for scan in [1usize, 2, 4, 8, 16, 24, 32, 48, 64, 128] {
        assert_eq!(
            TestApi.reader_pool_thread_count(scan),
            1,
            "default reader count must not grow with a {scan}-thread scan pool"
        );
    }
}

#[test]
fn filesystem_reader_crew_honors_explicit_config_without_env() {
    assert_eq!(
        TestApi.configured_reader_pool_thread_count(16, NonZeroUsize::new(3).unwrap()),
        3
    );
    assert_eq!(
        TestApi.configured_reader_pool_thread_count(2, NonZeroUsize::new(8).unwrap()),
        2,
        "explicit reader count is bounded by the scan pool instead of oversubscribing it"
    );
}
