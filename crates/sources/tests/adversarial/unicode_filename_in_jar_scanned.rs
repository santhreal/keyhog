//! Unicode entry names inside jar archives must unpack and scan.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn unicode_filename_in_jar_scanned() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = File::create(dir.path().join("i18n.jar")).expect("create");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("配置/秘密.env", opts).expect("start");
    zip.write_all(b"GITHUB_TOKEN=ghp_unicodeJarEntryTest000000000001
")
        .expect("write");
    zip.finish().expect("finish");

    let bodies: Vec<String> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();
    assert!(
        bodies.iter().any(|b| b.contains("ghp_unicodeJarEntryTest")),
        "unicode jar entry must be scanned; got {bodies:?}"
    );
}
