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
        bodies
            .iter()
            .any(|b| b.contains(concat!("AK", "IAR7VXNPLMQ3HSKWJT"))),
        "gzip payload must decompress to scannable text; got {bodies:?}"
    );
}

#[test]
fn jar_archive_inner_text_is_scanned() {
    let dir = tempfile::tempdir().unwrap();
    let secret = b"SLACK_TOKEN=xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx\n";
    let file = File::create(dir.path().join("app.jar")).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("META-INF/config.env", options).unwrap();
    zip.write_all(secret).unwrap();
    zip.finish().unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let bodies: Vec<String> = source
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();
    assert!(
        bodies
            .iter()
            .any(|b| b.contains(concat!("xox", "b-1234567890"))),
        ".jar archives must unpack inner text; got {bodies:?}"
    );
    let paths: Vec<_> = source
        .chunks()
        .flatten()
        .filter_map(|c| c.metadata.path.clone())
        .collect();
    assert!(
        paths.iter().any(|p| p.contains("config.env")),
        "archive entry path must be surfaced; got {paths:?}"
    );
}

#[test]
fn jar_binary_entry_extracts_printable_strings() {
    let dir = tempfile::tempdir().unwrap();
    let mut binary = Vec::new();
    binary.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);
    binary.extend_from_slice(b"HARDCODED_API=AKIAIOSFODNN7EXAMPLE");
    binary.extend_from_slice(&[0xff, 0xfe]);

    let file = File::create(dir.path().join("binary.jar")).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("classes/Secret.class", options).unwrap();
    zip.write_all(&binary).unwrap();
    zip.finish().unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let chunks: Vec<_> = source.chunks().flatten().collect();
    assert!(
        chunks.iter().any(|c| {
            c.metadata.source_type == "filesystem/archive-binary"
                && c.data.contains(concat!("AK", "IAIOSFODNN7EXAMPLE"))
        }),
        "binary archive entries must run printable-string extraction; got {chunks:?}"
    );
}

#[test]
fn archive_at_symlink_path_is_not_opened() {
    let dir = tempfile::tempdir().unwrap();
    let secret = b"GITHUB_TOKEN=ghp_symlinkBypassShouldNotReadThis000000000000\n";
    let outer = tempfile::tempdir().unwrap();
    let real = outer.path().join("real.jar");
    let file = File::create(&real).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("inner.env", options).unwrap();
    zip.write_all(secret).unwrap();
    zip.finish().unwrap();

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&real, dir.path().join("linked.jar")).unwrap();
        let source = FilesystemSource::new(dir.path().to_path_buf());
        let count = source.chunks().flatten().count();
        assert_eq!(
            count, 0,
            "symlinked archive paths must be skipped (link-swap defense)"
        );
    }
}
