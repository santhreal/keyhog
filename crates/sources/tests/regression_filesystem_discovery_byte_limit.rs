//! Regression coverage for bounded filesystem discovery used by `scan-system`.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs;

fn chunk_payloads(source: &FilesystemSource) -> Vec<String> {
    source
        .chunks()
        .map(|row| {
            row.expect("bounded discovery fixture must stay readable")
                .data
                .as_str()
                .to_owned()
        })
        .collect()
}

/// An exact metadata-byte boundary must remain complete instead of reporting a partial walk.
#[test]
fn exact_boundary_scans_the_file_without_marking_discovery_partial() {
    let dir = tempfile::tempdir().unwrap();
    let payload = "exactly-sixteen!";
    assert_eq!(payload.len(), 16);
    fs::write(dir.path().join("exact.txt"), payload).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf())
        .with_discovery_byte_limit(payload.len() as u64);
    assert_eq!(chunk_payloads(&source), [payload]);
    assert!(!source.discovery_limit_reached());
}

/// The first over-budget file must reach the chunk guard so the caller can refuse it visibly.
#[test]
fn over_boundary_file_is_admitted_and_marks_discovery_partial() {
    let dir = tempfile::tempdir().unwrap();
    let payload = "seventeen-bytes!!";
    assert_eq!(payload.len(), 17);
    fs::write(dir.path().join("over.txt"), payload).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_discovery_byte_limit(16);
    assert_eq!(chunk_payloads(&source), [payload]);
    assert!(source.discovery_limit_reached());
}

/// Discovery must stop after the boundary file instead of enumerating the entire remaining tree.
#[test]
fn discovery_stops_after_the_first_file_that_crosses_the_limit() {
    let dir = tempfile::tempdir().unwrap();
    let payload = "x".repeat(64);
    for index in 0..10 {
        fs::write(dir.path().join(format!("{index:02}.txt")), &payload).unwrap();
    }

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_discovery_byte_limit(64);
    let chunks = chunk_payloads(&source);
    assert_eq!(chunks.len(), 2);
    assert!(chunks.iter().all(|chunk| chunk == &payload));
    assert!(source.discovery_limit_reached());
}

/// Empty files must consume discovery budget so an attacker cannot force an unbounded metadata walk.
#[test]
fn zero_byte_files_cannot_evade_the_discovery_limit() {
    let dir = tempfile::tempdir().unwrap();
    for index in 0..10 {
        fs::write(dir.path().join(format!("empty-{index:02}.txt")), []).unwrap();
    }

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_discovery_byte_limit(2);
    assert!(chunk_payloads(&source).is_empty());
    assert!(source.discovery_limit_reached());
}
