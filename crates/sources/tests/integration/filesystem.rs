use keyhog_core::merkle_index::MerkleIndex;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Helper: read mtime_ns the same way FilesystemSource does so the test
/// stores a value the source's fast-path will actually match.
fn mtime_ns(path: &std::path::Path) -> u64 {
    let m = fs::metadata(path).unwrap().modified().unwrap();
    let d = m.duration_since(std::time::UNIX_EPOCH).unwrap();
    u64::try_from(d.as_secs() as u128 * 1_000_000_000 + d.subsec_nanos() as u128)
        .unwrap_or(u64::MAX)
}

#[test]
fn scan_temp_directory() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("config.py"),
        "API_KEY = 'xoxb-1234567890-1234567890-abcdefghijABCDEFGHIJklmn'",
    )
    .unwrap();
    fs::write(dir.path().join("image.png"), [0x89, 0x50, 0x4e, 0x47]).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(chunks.len(), 1); // Only config.py, not image.png.
    assert!(chunks[0].data.contains("xoxb"));
}

#[test]
fn scan_mmap_file() {
    let dir = tempfile::tempdir().unwrap();

    // Create a file large enough to trigger mmap
    let large_content = "SECRET_KEY = ".to_string() + &"x".repeat(8192);
    fs::write(dir.path().join("large_config.py"), &large_content).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(chunks.len(), 1);
    assert!(chunks[0].data.contains("SECRET_KEY"));
}

#[test]
#[cfg(unix)]
fn symlink_loops_are_not_followed() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("nested");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("config.env"), "LEGENDARY_LOOP=present").unwrap();
    symlink(dir.path(), nested.join("loop")).unwrap();

    let chunks: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(chunks.len(), 1);
    assert!(chunks[0].data.contains("LEGENDARY_LOOP"));
}

#[test]
fn broken_utf8_is_handled_gracefully() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broken.txt");
    // Valid prefix, followed by invalid UTF-8 (0xFF), then more text
    let mut content = b"prefix_".to_vec();
    content.push(0xFF);
    content.extend_from_slice(b"_suffix");
    fs::write(&path, content).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let chunks: Vec<_> = source.chunks().filter_map(|r| r.ok()).collect();

    assert!(
        !chunks.is_empty(),
        "Broken UTF-8 file should still produce a chunk"
    );
    // The decoder should use lossy conversion or replacement
    assert!(chunks[0].data.contains("prefix_"));
    assert!(chunks[0].data.contains("_suffix"));
}

#[test]
fn deep_recursive_symlinks_do_not_crash() {
    let dir = tempfile::tempdir().unwrap();
    let mut current = dir.path().to_path_buf();

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        // Create a chain of 50 symlinks
        for i in 0..50 {
            let next = dir.path().join(format!("link_{}", i));
            if symlink(&current, &next).is_err() {
                break;
            }
            current = next;
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::symlink_dir;
        // Create a chain of 5 symlinks (Windows has tighter limits/permissions)
        for i in 0..5 {
            let next = dir.path().join(format!("link_{}", i));
            if symlink_dir(&current, &next).is_err() {
                break;
            }
            current = next;
        }
    }

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

    // Should not crash and should complete in reasonable time
    assert!(chunks.is_empty() || chunks.len() < 100);
}

#[test]
fn default_excludes_skip_lock_and_cache_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("config.py"),
        "SECRET = 'real_secret_here_12345'",
    )
    .unwrap();
    fs::write(
        dir.path().join("package-lock.json"),
        "{}
",
    )
    .unwrap();
    fs::write(dir.path().join("yarn.lock"), "").unwrap();
    fs::write(
        dir.path().join("cache.json"),
        "{}
",
    )
    .unwrap();
    fs::write(dir.path().join("app.min.js"), "var x=1").unwrap();
    fs::write(dir.path().join("styles.min.css"), "body{}").unwrap();

    let excludes = vec![
        "**/package-lock.json*".to_string(),
        "**/yarn.lock".to_string(),
        "**/*.min.js".to_string(),
        "**/*.min.css".to_string(),
        "**/cache.json".to_string(),
    ];
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_ignore_paths(excludes);
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

    assert_eq!(chunks.len(), 1);
    assert!(chunks[0].data.contains("real_secret_here_12345"));
}

#[test]
fn default_excludes_skip_build_and_dependency_dirs() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("main.py"), "SECRET = 'found_it'").unwrap();

    let node_modules = dir.path().join("node_modules");
    fs::create_dir_all(&node_modules).unwrap();
    fs::write(node_modules.join("bad.js"), "SECRET = 'should_skip'").unwrap();

    let dist = dir.path().join("dist");
    fs::create_dir_all(&dist).unwrap();
    fs::write(dist.join("bundle.js"), "SECRET = 'also_skip'").unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

    assert_eq!(chunks.len(), 1);
    assert!(chunks[0].data.contains("found_it"));
}

#[test]
fn merkle_skip_avoids_reading_unchanged_files() {
    // Pre-populate the index with the live (mtime, size) of a file. On
    // the next walk, the metadata fast-path must skip the file BEFORE
    // it is read — observable as zero emitted chunks plus a non-zero
    // skip counter.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("env.txt");
    fs::write(&p, "AWS_KEY=AKIAIOSFODNN7EXAMPLE").unwrap();
    let canonical = p.canonicalize().unwrap();
    let size = fs::metadata(&canonical).unwrap().len();
    let m = mtime_ns(&canonical);

    let idx = Arc::new(MerkleIndex::empty());
    idx.record_with_metadata(canonical.clone(), m, size, [0u8; 32]);

    let source = FilesystemSource::new(dir.path().to_path_buf())
        .with_merkle_skip(idx.clone());
    let counter = source.skipped_counter();
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

    assert!(chunks.is_empty(), "unchanged file should not yield a chunk");
    assert_eq!(counter.load(Ordering::Relaxed), 1);
}

#[test]
fn merkle_skip_does_not_fire_when_size_drifts() {
    // Same path, same mtime, different recorded size — must NOT skip.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("env.txt");
    fs::write(&p, "AWS_KEY=AKIAIOSFODNN7EXAMPLE").unwrap();
    let canonical = p.canonicalize().unwrap();
    let m = mtime_ns(&canonical);

    let idx = Arc::new(MerkleIndex::empty());
    // Record with a deliberately wrong size so the fast-path must miss.
    idx.record_with_metadata(canonical, m, /*size=*/ 1, [0u8; 32]);

    let source = FilesystemSource::new(dir.path().to_path_buf())
        .with_merkle_skip(idx);
    let counter = source.skipped_counter();
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

    assert_eq!(chunks.len(), 1, "size mismatch must force a re-read");
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[test]
fn merkle_skip_chunks_carry_live_metadata() {
    // For files that ARE read, the emitted chunk must carry the live
    // mtime + size so the orchestrator can refresh the cache entry.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("env.txt");
    fs::write(&p, "AWS_KEY=AKIAIOSFODNN7EXAMPLE").unwrap();
    let canonical = p.canonicalize().unwrap();
    let size = fs::metadata(&canonical).unwrap().len();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(chunks.len(), 1);
    let meta = &chunks[0].metadata;
    assert!(meta.mtime_ns.is_some(), "mtime_ns should be populated by FilesystemSource");
    assert_eq!(meta.size_bytes, Some(size));
}
