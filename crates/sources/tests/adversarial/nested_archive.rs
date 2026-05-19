//! Archive adversarial coverage for the filesystem source.
//!
//! `.zip` is listed in `SKIP_EXTENSIONS` today, so the archive-unpack branch
//! in `filesystem.rs` is not exercised via normal directory walks. These tests
//! pin that contract and verify gzip decompression still surfaces inner text.

use flate2::write::GzEncoder;
use flate2::Compression;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn write_gzip(path: &Path, plaintext: &[u8]) {
    let file = File::create(path).unwrap();
    let mut enc = GzEncoder::new(file, Compression::default());
    enc.write_all(plaintext).unwrap();
    enc.finish().unwrap();
}

#[test]
fn zip_extension_skipped_in_default_filesystem_walk() {
    let dir = tempfile::tempdir().unwrap();
    let secret = b"GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab\n";
    let file = File::create(dir.path().join("outer.zip")).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("config.env", options).unwrap();
    zip.write_all(secret).unwrap();
    zip.finish().unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let count = source.chunks().flatten().count();
    assert_eq!(
        count, 0,
        ".zip files are in SKIP_EXTENSIONS — archive unpack path is not reached via walk"
    );
}

#[test]
fn gzip_member_secret_is_decompressed_to_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let secret = b"AWS_ACCESS_KEY_ID=AKIAR7VXNPLMQ3HSKWJT\n";
    write_gzip(&dir.path().join("secrets.env.gz"), secret);

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let bodies: Vec<String> = source
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();
    assert!(
        bodies.iter().any(|b| b.contains("AKIAR7VXNPLMQ3HSKWJT")),
        "gzip payload must decompress to scannable text; got {bodies:?}"
    );
}
