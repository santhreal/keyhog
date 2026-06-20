//! Single archive entries declaring uncompressed size above max_file_size are skipped.

use super::support::collect_chunks;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn zip_entry_over_per_file_cap_skipped() {
    let dir = tempfile::tempdir().expect("tempdir");

    let control = dir.path().join("control.zip");
    let file = File::create(&control).expect("create control");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("tiny-ok.txt", opts).expect("start ok");
    zip.write_all(b"SAFE=1\n").expect("write ok");
    zip.finish().expect("finish control");

    let bomb = dir.path().join("bigentry.zip");
    let file = File::create(&bomb).expect("create bomb");
    let mut zip = ZipWriter::new(file);
    zip.start_file("huge.bin", opts).expect("start huge");
    zip.write_all(&vec![b'H'; 2048]).expect("write huge");
    zip.finish().expect("finish bomb");

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(512);
    let bodies: Vec<String> = collect_chunks(&source)
        .into_iter()
        .map(|c| c.data.to_string())
        .collect();

    assert!(
        bodies.iter().any(|b| b.contains("SAFE=1")),
        "control archive with only small entries must still unpack"
    );
    assert!(
        !bodies.iter().any(|b| b.contains('H') && b.len() > 100),
        "oversized archive entry must be skipped entirely; got {bodies:?}"
    );
}
