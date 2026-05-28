//! R5-T archive adversarial: zip duplicate names handled without panic.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn r5t_zip_duplicate_entry_names_no_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let zip_path = dir.path().join("dup.zip");
    let file = File::create(&zip_path).expect("create");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for content in [b"first\n", b"second\n"] {
        zip.start_file("dup.txt", opts).expect("start");
        zip.write_all(content).expect("write");
    }
    zip.finish().expect("finish");
    let _count = FilesystemSource::new(dir.path().to_path_buf()).chunks().flatten().count();
}
