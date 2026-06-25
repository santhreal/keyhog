//! R5-T archive adversarial: tar.gz with small text member is scanned.

use crate::support::split_chunk_results;
use flate2::write::GzEncoder;
use flate2::Compression;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::io::Write;

#[test]
fn r5t_tar_gz_single_small_member_scanned() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut tar_builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path("inner.env").expect("path");
    header.set_size(24);
    header.set_cksum();
    tar_builder
        .append(&header, &b"AWS=AKIAQYLPMN5HFIQR7XYA\n"[..])
        .expect("append");
    let tar_bytes = tar_builder.into_inner().expect("tar");
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).expect("gzip");
    let gz = encoder.finish().expect("finish");
    std::fs::write(dir.path().join("fixture.tar.gz"), gz).expect("write");
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid tar.gz member should not emit SourceError rows: {errors:?}"
    );
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("AKIAQYLPMN5HFIQR7XYA")),
        "tar.gz member must be scanned; got {chunks:?}"
    );
    assert!(
        chunks.iter().any(|chunk| chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|path| path.contains("fixture.tar.gz//inner.env"))),
        "tar.gz archive entry path must be surfaced; got {chunks:?}"
    );
}
