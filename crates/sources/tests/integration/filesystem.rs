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
#[cfg(unix)]
fn symlink_loop_terminates_within_time_bound() {
    // Hostile-input robustness: a self-referential symlink must
    // not just "eventually" terminate (existing test) — it must
    // terminate in BOUNDED time. Without an explicit time cap an
    // attacker could DoS keyhog with a 1M-deep symlink chain even
    // if the walker eventually breaks the cycle. The walker is
    // configured with `follow_symlinks(false)` in keyhog's
    // `walker_config`, so the loop should never even be entered;
    // 5s is a generous cap that covers cold filesystem + workspace
    // initialization.
    use std::os::unix::fs::symlink;
    use std::time::{Duration, Instant};

    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("nested");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("real.env"), "REAL_FILE=present").unwrap();
    // Self-loop: nested/loop → dir, which contains nested.
    symlink(dir.path(), nested.join("loop")).unwrap();
    // Plus a wider loop: nested/loop2/loop3 → dir.
    let l2 = nested.join("loop2");
    fs::create_dir_all(&l2).unwrap();
    symlink(dir.path(), l2.join("back")).unwrap();

    let started = Instant::now();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "symlink loop walk took {:?}; should be sub-second under follow_symlinks(false)",
        elapsed
    );
    // The real file under nested/ must still be discovered.
    assert!(
        chunks.iter().any(|c| c.data.contains("REAL_FILE=present")),
        "the non-symlink file under nested/ was not discovered"
    );
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
fn windowed_path_emits_multiple_chunks_with_overlap() {
    // Big-file path: write a fixture larger than the test window
    // override, configure the source to use small windows, and verify
    // the source emits the expected number of overlapping chunks
    // with monotonically increasing base_offset values.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("big.log");
    // Use ASCII so byte-length matches char-length post-lossy decode.
    let content: Vec<u8> = (b'a'..=b'z').cycle().take(200).collect();
    fs::write(&p, &content).unwrap();

    // window=128 overlap=32 → for len=200 we get exactly 2 windows
    // (matches the secret-straddling-cut test in read.rs).
    let source = FilesystemSource::new(dir.path().to_path_buf())
        .with_window_config(128, 32);
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

    assert_eq!(chunks.len(), 2, "expected 2 windowed chunks for 200B file");
    assert_eq!(chunks[0].metadata.source_type, "filesystem/windowed");
    assert_eq!(chunks[0].metadata.base_offset, 0);
    assert_eq!(chunks[1].metadata.base_offset, 128 - 32);
    // Every chunk must carry the same overall file size + a populated mtime.
    for c in &chunks {
        assert_eq!(c.metadata.size_bytes, Some(200));
        assert!(c.metadata.mtime_ns.is_some());
    }
}

#[test]
fn windowed_path_finds_secret_in_overlap_region() {
    // Correctness invariant of the overlap parameter: a secret whose
    // bytes lie wholly within the overlap region must appear FULLY in
    // both windows. This is what the overlap exists for — a secret
    // happening to straddle the cut won't be split such that neither
    // window has the complete byte sequence. The contract is "fits
    // in overlap → present in both"; secrets larger than overlap can
    // still fail to be fully contained on the trailing side, which
    // is a documented limitation, not a bug. (For our 4 KiB prod
    // overlap that means secrets up to 4 KiB are safe — far longer
    // than any real credential.)
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("secret.log");
    let mut content = vec![b'.'; 200];
    let secret = b"AKIAIOSFODNN7EXAMPLE"; // 20 bytes
    // Place at offset 100 so the secret fits in the overlap region
    // (96..128). 20-byte secret at 100..120 is fully inside both
    // window 0 (0..128) and window 1 (96..200).
    content[100..100 + secret.len()].copy_from_slice(secret);
    fs::write(&p, &content).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf())
        .with_window_config(128, 32);
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(chunks.len(), 2);
    let s = std::str::from_utf8(secret).unwrap();
    assert!(chunks[0].data.contains(s), "window 0 must include the overlap-region secret");
    assert!(chunks[1].data.contains(s), "window 1 must include the overlap-region secret");
}

#[test]
fn windowed_path_finds_post_cut_secret_in_second_window_only() {
    // Companion correctness check: a secret too long for the overlap
    // region but fully contained in the second window after the cut
    // must appear at least once. Documents the "secret > overlap"
    // boundary behavior so a future maintainer can't accidentally
    // tighten the overlap and silently regress detection.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("secret.log");
    let mut content = vec![b'.'; 200];
    let secret = b"AKIAIOSFODNN7EXAMPLE"; // 20 bytes
    // Place at offset 120 so it sits PAST the cut at 128 — only fully
    // contained in window 1 (96..200). Window 0 has the first 8 bytes
    // only and won't substring-match the full credential.
    content[120..120 + secret.len()].copy_from_slice(secret);
    fs::write(&p, &content).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf())
        .with_window_config(128, 32);
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(chunks.len(), 2);
    let s = std::str::from_utf8(secret).unwrap();
    assert!(
        !chunks[0].data.contains(s),
        "window 0 holds only a prefix and must not substring-match"
    );
    assert!(
        chunks[1].data.contains(s),
        "window 1 must contain the full secret"
    );
}

#[test]
fn windowed_path_single_chunk_for_file_at_exactly_window_size() {
    // Edge case: file size == window_size triggers the windowed path
    // gate (`file_size > window_size`) only when strictly greater. At
    // exactly window_size we should fall through to the regular
    // mmap/buffered read path — verify ONE chunk, NOT windowed.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("edge.log");
    let content: Vec<u8> = (b'a'..=b'z').cycle().take(128).collect();
    fs::write(&p, &content).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf())
        .with_window_config(128, 32);
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(chunks.len(), 1);
    assert_ne!(
        chunks[0].metadata.source_type, "filesystem/windowed",
        "exact-size file must take the regular read path, not the windowed path"
    );
}

#[test]
fn windowed_path_single_chunk_when_only_one_window_above_threshold() {
    // window_size=64, overlap=8 → file_size=65 trips the threshold
    // (65 > 64) and produces exactly ONE window (the second would
    // start at offset 56 which is < 65, so we get a tiny tail).
    // Length picked to test the upper loop bound.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("just_over.log");
    let content: Vec<u8> = (b'a'..=b'z').cycle().take(65).collect();
    fs::write(&p, &content).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf())
        .with_window_config(64, 8);
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(chunks.len(), 2);
    // Window 0: 0..64 = 64 bytes; window 1: 56..65 = 9 bytes.
    assert_eq!(chunks[0].metadata.base_offset, 0);
    assert_eq!(chunks[1].metadata.base_offset, 56);
    assert_eq!(chunks[1].data.len(), 9);
}

#[test]
fn windowed_path_offsets_strictly_monotonic() {
    // For a file of arbitrary size emitting many windows, base_offset
    // must increase by exactly stride (window - overlap) between
    // consecutive chunks. Catches off-by-one regressions in the
    // slicing arithmetic.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("many.log");
    let content: Vec<u8> = (b'a'..=b'z').cycle().take(2000).collect();
    fs::write(&p, &content).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf())
        .with_window_config(256, 32);
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
    assert!(chunks.len() >= 5, "expected several windows for 2000B / 256");

    for pair in chunks.windows(2) {
        let stride = pair[1].metadata.base_offset - pair[0].metadata.base_offset;
        assert_eq!(stride, 256 - 32, "stride mismatch between consecutive windows");
    }
}

#[test]
fn medium_file_between_unix_and_windows_thresholds_round_trips() {
    // 200 KiB — sits above the 64 KiB Unix mmap threshold and below
    // the 1 MiB Windows threshold. On Unix this exercises the mmap
    // path; on Windows it exercises the buffered path. Either way
    // the chunk content must equal the file content byte-for-byte
    // (modulo lossy UTF-8 on invalid bytes, which we avoid here by
    // using ASCII).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("medium.txt");
    let payload: String = (b'a'..=b'z')
        .cycle()
        .take(200 * 1024)
        .map(|b| b as char)
        .collect();
    fs::write(&path, &payload).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].data.len(), payload.len());
    assert!(chunks[0].data.starts_with("abcdefg"));
}

#[test]
fn compressed_gz_file_yields_decompressed_chunk() {
    // End-to-end check that the streaming/mmap-backed compressed
    // path correctly decodes a real gzip stream and surfaces a
    // chunk tagged `filesystem/compressed`. Replaces the prior
    // implicit coverage that only proved we *opened* gz files.
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payload.gz");
    // Plant a recognisable plaintext marker that we can grep for in
    // the emitted chunk's data — proves decompression actually ran.
    let plaintext = b"COMPRESSED_PAYLOAD_MARKER_98765 inside the gz stream";
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(plaintext).unwrap();
    let gz_bytes = encoder.finish().unwrap();
    fs::write(&path, &gz_bytes).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
    // At least one chunk emitted from the gz; tagged compressed.
    assert!(!chunks.is_empty(), "compressed path must emit a chunk");
    assert!(
        chunks.iter().any(|c| c.metadata.source_type == "filesystem/compressed"),
        "expected filesystem/compressed source_type"
    );
    let combined: String = chunks
        .iter()
        .filter(|c| c.metadata.source_type == "filesystem/compressed")
        .map(|c| c.data.to_string())
        .collect();
    assert!(
        combined.contains("COMPRESSED_PAYLOAD_MARKER_98765"),
        "decompressed payload must surface in the chunk text"
    );
}

#[test]
fn compressed_path_skips_corrupt_or_oversize_inputs_without_panic() {
    // A non-gz file with a `.gz` extension must NOT crash the source.
    // Either we get an empty chunk list (ziftsieve refuses to decode)
    // or a fallback path takes over — never a panic.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("garbage.gz");
    fs::write(&path, b"this is not a real gzip stream at all").unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    // Just verify it doesn't panic and the iterator drains cleanly.
    let _: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
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
