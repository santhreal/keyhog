//! A file named like a compressed tarball but holding a single compressed file
//! must still be scanned.
//!
//! REGRESSION (Devin #41): `force_tar` treated every `*.tar.gz` name as an
//! unconditional tarball on the streaming path. A misnamed single gzip stream
//! then failed tar enumeration and returned without falling through to the
//! leaf-scan path, silently losing credentials in the decompressed bytes.

use crate::support::split_chunk_results;
use flate2::write::GzEncoder;
use flate2::Compression;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::io::Write;

const SECRET: &str = "AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA";

#[test]
fn misnamed_targz_single_compressed_file_is_scanned() {
    let dir = tempfile::tempdir().unwrap();
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(SECRET.as_bytes()).unwrap();
    enc.write_all(b"\n").unwrap();
    let gz = enc.finish().unwrap();
    // Name says tarball; payload is a plain gzip-compressed text file.
    std::fs::write(dir.path().join("bundle.tar.gz"), gz).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        chunks.iter().any(|chunk| chunk.data.contains(SECRET)),
        "misnamed single compressed file must be leaf-scanned; chunks={chunks:?} errors={errors:?}"
    );
    assert!(
        errors
            .iter()
            .all(|error| !error.to_string().contains("failed to read tar entries")),
        "misnamed single compressed file must not die on tar enumeration; errors={errors:?}"
    );
}
