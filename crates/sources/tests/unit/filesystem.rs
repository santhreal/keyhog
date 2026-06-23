use keyhog_core::{Source, SourceError};
use keyhog_sources::testing::{SourceTestApi, TestApi};
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
    assert_eq!(chunks[0].metadata.source_type, "filesystem");
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
fn filesystem_reader_crew_is_a_small_fixed_count_that_never_scales_with_scan_pool() {
    // PERF-parallel_cores: the dedicated file-reader crew must NOT grow with
    // the scan pool. The old sizing `clamp(scan_threads/2, 2, 16)` ran a SECOND
    // CPU pool on top of the scan pool (16 scan + 8 reader = 24 on 16 cores;
    // 32 + 16 = 48), oversubscribing cores and capping multicore scaling at
    // ~4.7x@16t (regressing at 32t). The crew is now a small FIXED count capped
    // at MAX_READER_THREADS (4): mostly parked on channel backpressure / read(2),
    // it overlaps I/O with scanning without claiming scan cores.

    // 1-thread scan needs only 1 reader (no oversubscription possible).
    assert_eq!(TestApi.reader_pool_thread_count(1), 1);
    // Small pools: floored at 2 so a single reader stalling on a slow file
    // can't starve the consumer.
    assert_eq!(TestApi.reader_pool_thread_count(2), 2);
    assert_eq!(TestApi.reader_pool_thread_count(4), 2);
    assert_eq!(TestApi.reader_pool_thread_count(8), 2);
    // The crew is ~1/4 of the cores (the I/O-overlap budget), NOT scan/2.
    assert_eq!(TestApi.reader_pool_thread_count(16), 4);
    // CRITICAL: above the cap the crew stops growing, so it can NEVER become a
    // second full pool. (old formula returned 16 at scan=32/64; new crew caps at 4.)
    assert_eq!(TestApi.reader_pool_thread_count(32), 4);
    assert_eq!(TestApi.reader_pool_thread_count(64), 4);
    assert_eq!(TestApi.reader_pool_thread_count(128), 4);

    // The defining property the PERF tripwire protects: the reader crew is a
    // SMALL slice of the machine that never balloons with the scan pool. The
    // old `scan/2` sizing put readers + scan at ~1.5x cores (the
    // oversubscription that capped 16t scaling and regressed at 32t); the crew
    // is now <= 1/4 of the scan pool (capped at MAX_READER_THREADS) for every
    // realistic host, so reader + scan stays within the machine.
    for scan in [8usize, 16, 24, 32, 48, 64, 128] {
        let readers = TestApi.reader_pool_thread_count(scan);
        assert!(
            readers <= 4,
            "reader crew {readers} for {scan} scan threads exceeds the fixed cap; \
             that reintroduces the PERF-parallel_cores oversubscription"
        );
        assert!(
            readers * 4 <= scan + 4,
            "reader crew {readers} for {scan} scan threads is more than ~1/4 of the \
             pool; that is the old scan/2 oversubscription class"
        );
        assert!(
            readers < scan,
            "reader crew must stay below the scan pool on large hosts"
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
