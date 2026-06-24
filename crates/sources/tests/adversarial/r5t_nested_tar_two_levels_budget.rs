//! R5-T archive adversarial: nested tar entries are unpacked, not treated as
//! opaque binary blobs.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn r5t_nested_tar_two_levels_inner_entry_scanned() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut inner = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path("inner.env").expect("path");
    let secret = b"TAIL=AKIAQYLPMN5HFIQR7XYA\n";
    header.set_size(secret.len() as u64);
    header.set_cksum();
    inner.append(&header, &secret[..]).expect("append");
    let inner_bytes = inner.into_inner().expect("inner tar");

    let mut outer = tar::Builder::new(Vec::new());
    let mut outer_header = tar::Header::new_gnu();
    outer_header.set_path("nested.tar").expect("path");
    outer_header.set_size(inner_bytes.len() as u64);
    outer_header.set_cksum();
    outer
        .append(&outer_header, &inner_bytes[..])
        .expect("append outer");
    std::fs::write(
        dir.path().join("nested.tar"),
        outer.into_inner().expect("outer"),
    )
    .expect("write");

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .with_max_file_size(10 * 1024)
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "nested tar recall fixture should not emit SourceErrors; got {errors:?}"
    );
    let bodies: Vec<String> = chunks.iter().map(|c| c.data.to_string()).collect();
    assert!(
        bodies.iter().any(|b| b.contains("AKIAQYLPMN5HFIQR7XYA")),
        "nested tar inner entry must be scanned; got {bodies:?}"
    );
    let paths: Vec<_> = chunks
        .iter()
        .filter_map(|chunk| chunk.metadata.path.as_deref())
        .collect();
    assert!(
        paths
            .iter()
            .any(|path| path.contains("nested.tar//nested.tar//inner.env")),
        "nested tar metadata must include both archive levels; got {paths:?}"
    );
}
