//! Spawn N FilesystemSources in parallel via rayon and verify each one
//! sees only its own files. Catches the class of bug where a shared
//! global walker / cache leaks paths between concurrent scans.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use rayon::prelude::*;
use std::fs;

#[test]
fn rayon_parallel_filesystem_sources_dont_cross_contaminate() {
    // 8 isolated temp dirs, each with a unique marker file. Run each
    // through its own FilesystemSource on a rayon thread; assert every
    // result yields exactly the marker file with the matching content.
    let dirs: Vec<_> = (0..8u32)
        .map(|i| {
            let dir = tempfile::tempdir().unwrap();
            let marker = format!("MARKER_{i}_TOKEN_{}", i.wrapping_mul(0xdeadbeef));
            fs::write(
                dir.path().join("config.py"),
                format!("API_KEY = '{marker}'"),
            )
            .unwrap();
            (i, dir, marker)
        })
        .collect();

    dirs.par_iter().for_each(|(i, dir, expected_marker)| {
        let source = FilesystemSource::new(dir.path().to_path_buf());
        let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
        // Each isolated source must see exactly its own file.
        assert_eq!(chunks.len(), 1, "thread {i} got {} chunks", chunks.len());
        assert!(
            chunks[0].data.contains(expected_marker),
            "thread {i} did not see its own marker; saw: {}",
            chunks[0].data
        );
        // And must NOT see any other thread's marker.
        for (other_i, _, other_marker) in dirs.iter() {
            if *other_i == *i {
                continue;
            }
            assert!(
                !chunks[0].data.contains(other_marker),
                "thread {i} contaminated by thread {other_i}'s marker"
            );
        }
    });
}
