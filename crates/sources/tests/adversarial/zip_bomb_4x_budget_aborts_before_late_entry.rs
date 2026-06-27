//! Zip archives whose cumulative uncompressed size exceeds 4× max_file_size
//! must abort extraction before later entries are read (zip-bomb budget).

use crate::support::split_chunk_results;
use std::io::Write;

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};
use std::fs::File;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn zip_bomb_4x_budget_aborts_before_late_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let zip_path = dir.path().join("bomb.zip");
    let file = File::create(&zip_path).expect("create zip");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    const MAX_FILE_SIZE: u64 = 4 * 1024;
    for i in 0..6 {
        let name = format!("part{i}.txt");
        zip.start_file(name, opts).expect("start");
        let body = vec![b'Z'; MAX_FILE_SIZE as usize];
        zip.write_all(&body).expect("write");
    }
    zip.start_file("secret.env", opts).expect("start secret");
    zip.write_all(b"LEAK=AKIAQYLPMN5HFIQR7XYA\n")
        .expect("write secret");
    zip.finish().expect("finish");

    std::fs::write(dir.path().join("outside.txt"), "OUTSIDE=ok\n").expect("outside");

    // Hold the exclusive scan scope for the whole reset->scan->read window so a
    // concurrent test cannot reset or record into the process-global skip
    // counters mid-measurement (the canonical isolation primitive used by every
    // other counter-asserting archive test). Reset under the lease so the count
    // read back is this scan's alone -- without it the bare global delta
    // underflows to 0 when a parallel test resets the counter (a false failure).
    let _counter_guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(MAX_FILE_SIZE);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let bodies: Vec<String> = chunks.iter().map(|c| c.data.to_string()).collect();

    assert!(
        bodies.iter().any(|b| b.contains("OUTSIDE=ok")),
        "walk must continue after zip-bomb abort"
    );
    let archive_truncated = skip_counts().archive_truncated;
    assert!(
        archive_truncated >= 1,
        "zip-bomb budget must record an archive truncation in this scan; got {archive_truncated}"
    );
    assert_eq!(
        errors.len(),
        1,
        "zip-bomb budget abort must surface one SourceError"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("archive extraction")
            && error.contains("remaining entries were not scanned"),
        "zip-bomb SourceError must describe partial archive coverage, got {error:?}"
    );
    let archive_chunks = chunks
        .iter()
        .filter(|chunk| {
            chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|path| path.contains("bomb.zip//part"))
        })
        .count();
    assert!(
        archive_chunks > 0 && archive_chunks < 6,
        "zip-bomb budget must scan only the safe prefix; emitted {archive_chunks}"
    );
    assert!(
        !bodies
            .iter()
            .any(|b| b.contains("LEAK=AKIAQYLPMN5HFIQR7XYA")),
        "entry past 4× budget must never be extracted; got {bodies:?}"
    );
}
