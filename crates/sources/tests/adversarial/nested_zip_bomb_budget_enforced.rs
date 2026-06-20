//! Nested zip members still count toward the 4× uncompressed budget.

use super::support::collect_chunks;
use std::io::Write;

use keyhog_sources::FilesystemSource;
use std::fs::File;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn nested_zip_bomb_budget_enforced() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Inner zip with two 500-byte stored entries (total 1000 > 4×256 budget).
    let inner_path = dir.path().join("inner.zip");
    let inner_file = File::create(&inner_path).expect("inner");
    let mut inner = ZipWriter::new(inner_file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for i in 0..2 {
        inner
            .start_file(format!("chunk{i}.txt"), opts)
            .expect("start");
        inner.write_all(&vec![b'Q'; 500]).expect("write");
    }
    inner.finish().expect("finish inner");

    let outer_path = dir.path().join("outer.zip");
    let outer_file = File::create(&outer_path).expect("outer");
    let mut outer = ZipWriter::new(outer_file);
    outer.start_file("nested.zip", opts).expect("start nested");
    outer
        .write_all(&std::fs::read(&inner_path).expect("read inner"))
        .expect("embed");
    outer.start_file("tail-secret.env", opts).expect("tail");
    outer
        .write_all(b"TAIL=AKIAQYLPMN5HFIQR7XYA\n")
        .expect("tail write");
    outer.finish().expect("finish outer");

    let bodies: Vec<String> =
        collect_chunks(&FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(256))
            .into_iter()
            .map(|c| c.data.to_string())
            .collect();

    assert!(
        !bodies.iter().any(|b| b.contains("TAIL=AKIA")),
        "budget abort must prevent late zip entries; got {bodies:?}"
    );
}
