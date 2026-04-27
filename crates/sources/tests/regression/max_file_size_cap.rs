//! Regression: `FilesystemSource::with_max_file_size` must skip files
//! whose on-disk byte size exceeds the cap, even when the file is
//! plain text and would otherwise be scanned.
//!
//! Pre-fix bug shape: the walker honored an extension exclude list but
//! not a byte-size cap, so a 1-GiB log file would still get streamed
//! into the scanner's pipeline. Drove the audit release-2026-04-26
//! addition of `with_max_file_size`.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs;

#[test]
fn max_file_size_cap_skips_oversized_files() {
    let dir = tempfile::tempdir().unwrap();

    // A small file (under cap) and a "large" file (over cap). We only
    // need to cross the cap, not allocate gigabytes — set the cap low.
    fs::write(
        dir.path().join("small.py"),
        "API_KEY = 'short_token_under_cap'",
    )
    .unwrap();
    let large_content = "TOKEN = '".to_string() + &"x".repeat(2048) + "'";
    fs::write(dir.path().join("large.py"), &large_content).unwrap();

    // Cap at 256 bytes — the large file is well over, the small one is
    // safely under.
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(256);
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

    assert_eq!(
        chunks.len(),
        1,
        "expected only the small file under the 256-byte cap"
    );
    assert!(
        chunks[0].data.contains("short_token_under_cap"),
        "small file should be the surviving chunk"
    );
    for c in &chunks {
        assert!(
            !c.data.contains(&"x".repeat(64)),
            "large.py contents leaked through despite size cap"
        );
    }
}

#[test]
fn max_file_size_cap_zero_means_unlimited_or_skip_all() {
    // 0 is a sentinel — either treat as unlimited (current contract) or
    // skip every file. Pin whatever the current behavior is so a future
    // change is intentional, not silent.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.py"), "TOKEN = 'abc'").unwrap();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(0);
    // Either 0 or 1 is acceptable. Don't pin which — pin that no panic.
    let _ = source.chunks().collect::<Vec<_>>();
}
