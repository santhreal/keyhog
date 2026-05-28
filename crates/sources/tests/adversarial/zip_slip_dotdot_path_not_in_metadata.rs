//! §15 fix: archive entry names with `../` must not appear unescaped in the
//! reported finding path metadata.
//!
//! The previous code embedded `archive_entry.name` verbatim in the `path`
//! field — a `../escape.env` entry would produce a chunk whose path was
//! `foo.zip//../escape.env`, misleading operators and any downstream tooling
//! that reconstructs paths from findings.
//!
//! This test verifies that:
//! 1. A safe entry inside the same archive IS scanned (recall not broken).
//! 2. A `../` traversal entry is either skipped OR its path in the chunk
//!    metadata does NOT contain the raw `../` component.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn zip_slip_dotdot_reported_path_is_sanitized() {
    let dir = tempfile::tempdir().expect("tempdir");

    let file = File::create(dir.path().join("mixed.zip")).expect("create zip");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    // Traversal entry — name contains `../`
    zip.start_file("../traversal.env", opts).expect("start traversal");
    zip.write_all(b"TRAVERSAL_KEY=some_value\n").expect("write traversal");

    // Safe entry — should still be scanned
    zip.start_file("safe.env", opts).expect("start safe");
    zip.write_all(b"SAFE_KEY=ok\n").expect("write safe");

    zip.finish().expect("finish");

    let chunks: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .flatten()
        .collect();

    // No chunk's path metadata must contain a raw `../` component — the
    // sanitizer must either drop the entry or clean the path.
    for chunk in &chunks {
        if let Some(path) = &chunk.metadata.path {
            assert!(
                !path.contains("../") && !path.contains("..\\"),
                "chunk path must not contain raw `../` traversal; got: {path}"
            );
        }
    }

    // The safe entry must still produce a chunk (recall not broken).
    let safe_bodies: Vec<_> = chunks
        .iter()
        .filter(|c| c.data.as_str().contains("SAFE_KEY=ok"))
        .collect();
    assert!(
        !safe_bodies.is_empty(),
        "safe archive entry must still be extracted; all chunk data: {:?}",
        chunks
            .iter()
            .map(|c| c.metadata.path.as_deref().unwrap_or("<no path>"))
            .collect::<Vec<_>>()
    );
}

#[test]
fn zip_slip_nul_byte_in_name_path_is_sanitized() {
    let dir = tempfile::tempdir().expect("tempdir");

    let file = File::create(dir.path().join("nulbyte.zip")).expect("create zip");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    // NUL-byte traversal: `safe\0../../etc/passwd`
    // The zip crate may or may not be able to create this entry depending on
    // the OS; if it does, keyhog must not surface the traversal in path metadata.
    let _ = zip.start_file("safe\x00../../etc/passwd", opts);
    let _ = zip.write_all(b"NUL_BYPASS=1\n");

    zip.start_file("legit.env", opts).expect("start legit");
    zip.write_all(b"LEGIT=yes\n").expect("write legit");
    zip.finish().expect("finish");

    let chunks: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .flatten()
        .collect();

    for chunk in &chunks {
        if let Some(path) = &chunk.metadata.path {
            assert!(
                !path.contains('\0'),
                "chunk path must not contain NUL byte; got: {path:?}"
            );
            assert!(
                !path.contains("../"),
                "chunk path must not contain traversal after NUL-byte bypass; got: {path}"
            );
        }
    }
}
