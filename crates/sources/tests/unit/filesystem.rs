use keyhog_core::Source;
use keyhog_sources::{testing::reader_pool_thread_count, FilesystemSource};
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
fn filesystem_source_missing_path_yields_nothing() {
    let source = FilesystemSource::new(PathBuf::from("/tmp/keyhog-missing-path-xyzzy-999"));
    assert!(source.chunks().next().is_none());
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
    assert_eq!(reader_pool_thread_count(1), 1);
    // Small pools: floored at 2 so a single reader stalling on a slow file
    // can't starve the consumer.
    assert_eq!(reader_pool_thread_count(2), 2);
    assert_eq!(reader_pool_thread_count(4), 2);
    assert_eq!(reader_pool_thread_count(8), 2);
    // The crew is ~1/4 of the cores (the I/O-overlap budget), NOT scan/2.
    assert_eq!(reader_pool_thread_count(16), 4);
    // CRITICAL: above the cap the crew stops growing, so it can NEVER become a
    // second full pool. (old formula returned 16 at scan=32/64; new crew caps at 4.)
    assert_eq!(reader_pool_thread_count(32), 4);
    assert_eq!(reader_pool_thread_count(64), 4);
    assert_eq!(reader_pool_thread_count(128), 4);

    // The defining property the PERF tripwire protects: the reader crew is a
    // SMALL slice of the machine that never balloons with the scan pool. The
    // old `scan/2` sizing put readers + scan at ~1.5x cores (the
    // oversubscription that capped 16t scaling and regressed at 32t); the crew
    // is now <= 1/4 of the scan pool (capped at MAX_READER_THREADS) for every
    // realistic host, so reader + scan stays within the machine.
    for scan in [8usize, 16, 24, 32, 48, 64, 128] {
        let readers = reader_pool_thread_count(scan);
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
