//! R5-T archive adversarial: zip entry name with embedded null rejected.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn r5t_zip_slip_null_byte_in_name_not_extracted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let zip_path = dir.path().join("nullname.zip");
    let file = File::create(&zip_path).expect("create");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("safe\0../../etc/passwd", opts)
        .expect("start");
    zip.write_all(b"ROOT=1\n").expect("write");
    zip.finish().expect("finish");
    let bodies: Vec<String> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();
    assert!(
        !bodies.iter().any(|b| b.contains("ROOT=1")),
        "null-byte path must not extract; got {bodies:?}"
    );
}
