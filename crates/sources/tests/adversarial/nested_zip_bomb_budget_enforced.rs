//! Nested zip members still count toward the 4× uncompressed budget.

use crate::support::split_chunk_results;
use std::io::Write;

use keyhog_core::Source;
use keyhog_sources::{skip_counts, FilesystemSource};
use std::fs::File;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn nested_zip_bomb_budget_enforced() {
    let dir = tempfile::tempdir().expect("tempdir");

    const MAX_FILE_SIZE: u64 = 2 * 1024;

    // Inner zip stays small on disk, but expands past 4x MAX_FILE_SIZE.
    let inner_path = dir.path().join("inner.zip");
    let inner_file = File::create(&inner_path).expect("inner");
    let mut inner = ZipWriter::new(inner_file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for i in 0..6 {
        inner
            .start_file(format!("chunk{i}.txt"), opts)
            .expect("start");
        inner
            .write_all(&vec![b'Q'; MAX_FILE_SIZE as usize])
            .expect("write");
    }
    inner.start_file("inner-tail.env", opts).expect("tail");
    inner
        .write_all(b"INNER_TAIL=AKIAQYLPMN5HFIQR7XYA\n")
        .expect("inner tail write");
    inner.finish().expect("finish inner");

    let outer_path = dir.path().join("outer.zip");
    let outer_file = File::create(&outer_path).expect("outer");
    let mut outer = ZipWriter::new(outer_file);
    let outer_opts =
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    outer
        .start_file("nested.zip", outer_opts)
        .expect("start nested");
    outer
        .write_all(&std::fs::read(&inner_path).expect("read inner"))
        .expect("embed");
    outer
        .start_file("tail-secret.env", outer_opts)
        .expect("tail");
    outer
        .write_all(b"OUTER_TAIL=AKIAQYLPMN5HFIQR7XYA\n")
        .expect("tail write");
    outer.finish().expect("finish outer");
    std::fs::remove_file(&inner_path).expect("remove inner builder artifact");

    let before_truncated = skip_counts().archive_truncated;
    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .with_max_file_size(MAX_FILE_SIZE)
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let bodies: Vec<String> = chunks.iter().map(|c| c.data.to_string()).collect();

    let archive_truncation_delta = skip_counts()
        .archive_truncated
        .saturating_sub(before_truncated);
    assert!(
        archive_truncation_delta >= 1,
        "embedded ZIP member bytes must record an archive-bomb truncation in this scan; delta={archive_truncation_delta}"
    );
    assert_eq!(
        errors.len(),
        1,
        "nested ZIP budget abort must surface one SourceError"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("outer.zip//nested.zip")
            && error.contains("archive extraction")
            && error.contains("remaining entries were not scanned"),
        "nested ZIP budget SourceError must describe partial archive coverage, got {error:?}"
    );
    let nested_chunks = chunks
        .iter()
        .filter(|chunk| {
            chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|path| path.contains("outer.zip//nested.zip//chunk"))
        })
        .count();
    assert!(
        nested_chunks > 0 && nested_chunks < 6,
        "nested ZIP budget must scan only the safe prefix; emitted {nested_chunks}"
    );
    assert!(
        !bodies
            .iter()
            .any(|b| b.contains("INNER_TAIL=AKIAQYLPMN5HFIQR7XYA")),
        "nested entry past 4x budget must never be extracted; got {bodies:?}"
    );
    assert!(
        bodies
            .iter()
            .any(|b| b.contains("OUTER_TAIL=AKIAQYLPMN5HFIQR7XYA")),
        "outer ZIP siblings after a nested-archive truncation should still be scanned; got {bodies:?}"
    );
}
