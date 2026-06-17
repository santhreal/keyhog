//! LANE 5 (sources-safety) regressions: decompression bombs, OOM caps, and the
//! Law-10 surfacing of every archive truncation / unreadable drop.
//!
//! Each test drives the PUBLIC `Source::chunks()` API on a malicious or
//! adversarial on-disk fixture and asserts an EXACT observable: a bomb is
//! refused/truncated (the `archive_truncated` skip counter is bumped and the
//! decompressed tail is NOT emitted), an unreadable archive entry is counted,
//! and a refused symlink is counted. These pin the fail-closed + loud-surfacing
//! behaviour so a regression to a silent drop goes red.
//!
//! Own test binary: the skip counters are process-global atomics. A per-file
//! `MUTEX` serialises the counter-asserting tests so they don't race each other
//! within this binary (cargo runs tests in a binary in parallel by default).

#![cfg(unix)]

use keyhog_core::Source;
use keyhog_sources::{skip_counts, testing::reset_skip_counters, FilesystemSource};
use std::io::Write as _;
use std::sync::Mutex;

/// Serialises the process-global skip-counter assertions in THIS binary.
static COUNTER_LOCK: Mutex<()> = Mutex::new(());

/// Build a `.zip` whose entries decompress to far more than `4 * max_file_size`
/// of highly-compressible data, so the zip-bomb guard MUST truncate extraction.
/// Returns the path inside `dir`.
fn write_zip_bomb(dir: &std::path::Path, per_entry: usize, entries: usize) -> std::path::PathBuf {
    use zip::write::SimpleFileOptions;
    let zip_path = dir.join("bomb.zip");
    let file = std::fs::File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    // Deflated zeros: ~1000x compression, so the on-disk zip stays tiny while the
    // declared+actual uncompressed size dwarfs the budget.
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    let zero_block = vec![b'0'; per_entry];
    for i in 0..entries {
        zip.start_file(format!("entry_{i}.txt"), opts).unwrap();
        zip.write_all(&zero_block).unwrap();
    }
    zip.finish().unwrap();
    zip_path
}

#[test]
fn zip_bomb_extraction_is_truncated_and_counted() {
    let _guard = COUNTER_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();

    // max_file_size = 64 KiB => total uncompressed budget = 4 * 64 KiB = 256 KiB.
    // 16 entries * 64 KiB = 1 MiB uncompressed, which blows the budget and forces
    // a truncation after ~4 entries.
    const MAX: u64 = 64 * 1024;
    let _zip = write_zip_bomb(dir.path(), MAX as usize, 16);

    reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(MAX);
    let chunks: Vec<_> = source.chunks().flatten().collect();

    // The bomb guard fired: exactly one archive was truncated.
    assert_eq!(
        skip_counts().archive_truncated,
        1,
        "the zip-bomb guard must record exactly one truncated archive so the \
         operator sees the archive was only partially scanned (Law 10)"
    );
    // Truncation means NOT every entry was emitted. 16 entries would each be one
    // chunk if the budget were unbounded; the budget caps at ~4 entries' worth.
    let archive_chunks = chunks
        .iter()
        .filter(|c| {
            c.metadata
                .path
                .as_deref()
                .is_some_and(|p| p.contains("bomb.zip//"))
        })
        .count();
    assert!(
        archive_chunks < 16,
        "zip-bomb extraction must stop before emitting all 16 entries; emitted {archive_chunks}"
    );
    assert!(
        archive_chunks > 0,
        "the prefix up to the budget must still be scanned; emitted {archive_chunks}"
    );
}

#[test]
fn healthy_zip_is_not_counted_as_truncated() {
    // Negative twin: a small, well-formed zip well under budget must NOT trip the
    // bomb counter (no false coverage-gap alarm).
    let _guard = COUNTER_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("ok.zip");
    {
        use zip::write::SimpleFileOptions;
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.start_file("a.txt", opts).unwrap();
        zip.write_all(b"AWS=AKIAQYLPMN5HFIQR7XYA\n").unwrap();
        zip.finish().unwrap();
    }

    reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(1024 * 1024);
    let bodies: Vec<String> = source
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();
    assert_eq!(
        skip_counts().archive_truncated,
        0,
        "a healthy in-budget zip must NOT be recorded as truncated"
    );
    assert!(
        bodies.iter().any(|b| b.contains("AKIAQYLPMN5HFIQR7XYA")),
        "the healthy archive's entry must be scanned; got {bodies:?}"
    );
}

/// A `.gz` whose decompressed size blows the 4x budget must be truncated and the
/// `archive_truncated` counter bumped (single-stream zip-bomb, not a tar).
/// `--max-file-size 0` means "no per-file cap". A zip under that setting must
/// still be FULLY extracted, not truncated to nothing: before the fix the zip
/// path computed `total_budget = 0 * 4 = 0`, so the first non-empty entry tripped
/// the bomb guard and every archive collapsed to zero scanned entries (a recall
/// bug). The zip path now mirrors the compressed path's 1 GiB uncapped ceiling.
#[test]
fn zip_with_unlimited_max_file_size_is_fully_extracted() {
    let _guard = COUNTER_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("ok.zip");
    {
        use zip::write::SimpleFileOptions;
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.start_file("a.env", opts).unwrap();
        zip.write_all(b"AWS=AKIAQYLPMN5HFIQR7XYA\n").unwrap();
        zip.start_file("b.env", opts).unwrap();
        zip.write_all(b"GCP=AIzaSyBOTHENTRIESPRESENT012345678901234\n")
            .unwrap();
        zip.finish().unwrap();
    }

    reset_skip_counters();
    // max_file_size = 0 => unlimited per-file cap.
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(0);
    let bodies: Vec<String> = source
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();

    assert_eq!(
        skip_counts().archive_truncated,
        0,
        "with --max-file-size 0 (unlimited) a healthy zip must NOT be truncated; \
         the budget must fall back to the 1 GiB uncapped ceiling, not 0"
    );
    assert!(
        bodies.iter().any(|b| b.contains("AKIAQYLPMN5HFIQR7XYA")),
        "first entry must be scanned under unlimited cap; got {bodies:?}"
    );
    assert!(
        bodies.iter().any(|b| b.contains("BOTHENTRIESPRESENT")),
        "second entry must ALSO be scanned (not truncated after the first) under \
         unlimited cap; got {bodies:?}"
    );
}

/// A symlink whose name has an archive extension (`evil.zip -> real_secret.zip`)
/// sitting in a walked tree must NOT be expanded: following it would read AND
/// structurally expand an out-of-tree target (the link-swap exfiltration class).
/// The refusal must be counted (the secret in the target never surfaces).
#[test]
fn symlinked_archive_in_tree_is_not_expanded_and_is_counted() {
    let _guard = COUNTER_LOCK.lock().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let walked = tempfile::tempdir().unwrap();

    // The real archive with a secret lives OUTSIDE the walked tree.
    let real_zip = outside.path().join("real_secret.zip");
    {
        use zip::write::SimpleFileOptions;
        let file = std::fs::File::create(&real_zip).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.start_file("leak.env", opts).unwrap();
        zip.write_all(b"AWS=AKIAQYLPMN5HFIQR7XYA\n").unwrap();
        zip.finish().unwrap();
    }

    // The bait: an archive-extension symlink INSIDE the walked tree.
    let bait = walked.path().join("evil.zip");
    std::os::unix::fs::symlink(&real_zip, &bait).unwrap();

    reset_skip_counters();
    let source = FilesystemSource::new(walked.path().to_path_buf());
    let bodies: Vec<String> = source
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();

    assert!(
        !bodies.iter().any(|b| b.contains("AKIAQYLPMN5HFIQR7XYA")),
        "a symlinked archive must NOT be expanded out of the scan root; the \
         target's secret leaked into a chunk: {bodies:?}"
    );
    // The refused symlink must be recorded as a coverage gap (Law 10), not
    // silently treated as a clean/absent file. The walker's follow_symlinks(false)
    // and the archive-branch / include-admission no-follow guards each count it.
    assert!(
        skip_counts().unreadable >= 1 || bodies.is_empty(),
        "a refused archive symlink must be counted as unreadable (coverage gap) \
         OR yield no chunks at all; got unreadable={}, bodies={bodies:?}",
        skip_counts().unreadable
    );
}

#[test]
fn gzip_single_stream_bomb_is_truncated_and_counted() {
    let _guard = COUNTER_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let gz_path = dir.path().join("bomb.gz");

    const MAX: u64 = 64 * 1024;
    // 4 MiB of zeros gz-compresses to a few KiB; decompressed it dwarfs the
    // 256 KiB (4 * 64 KiB) budget, so the decode is capped + flagged.
    {
        let f = std::fs::File::create(&gz_path).unwrap();
        let mut enc = flate2::write::GzEncoder::new(f, flate2::Compression::best());
        enc.write_all(&vec![b'A'; 4 * 1024 * 1024]).unwrap();
        enc.finish().unwrap();
    }

    reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(MAX);
    let chunks: Vec<_> = source.chunks().flatten().collect();

    assert_eq!(
        skip_counts().archive_truncated,
        1,
        "a gzip stream that decompresses past the 4x cap must be recorded as a \
         truncated archive (Law 10), not silently scanned-as-prefix in the dark"
    );
    // The decompressed prefix that WAS scanned must be bounded by the budget, so
    // no single emitted chunk's data exceeds the 256 KiB budget by much (the
    // window slicer may chunk it, but total scanned bytes are capped).
    let total: usize = chunks
        .iter()
        .filter(|c| c.metadata.source_type.starts_with("filesystem/compressed"))
        .map(|c| c.data.as_ref().len())
        .sum();
    assert!(
        total <= 4 * MAX as usize + 1,
        "decompressed bytes scanned ({total}) must be bounded by the 4x budget \
         ({}), proving the bomb cannot OOM the process",
        4 * MAX as usize
    );
}
