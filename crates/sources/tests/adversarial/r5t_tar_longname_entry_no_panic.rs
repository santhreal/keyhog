//! R5-T archive adversarial: tar with long name entry does not panic.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn r5t_tar_longname_entry_no_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let long = "a".repeat(120);
    let mut tar_builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(3);
    tar_builder
        .append_data(&mut header, format!("{long}.txt"), &b"ok\n"[..])
        .expect("append");
    std::fs::write(
        dir.path().join("long.tar"),
        tar_builder.into_inner().expect("tar"),
    )
    .expect("write");
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "long-name tar entry should scan cleanly without SourceError rows: {errors:?}"
    );
    assert!(
        chunks.iter().any(|chunk| chunk.data.contains("ok\n")),
        "long-name tar entry payload must be scanned, got {chunks:?}"
    );
    assert!(
        chunks.iter().any(|chunk| chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|path| path.contains("long.tar//") && path.contains(&long))),
        "long-name tar entry path must preserve archive and entry names, got {chunks:?}"
    );
}
