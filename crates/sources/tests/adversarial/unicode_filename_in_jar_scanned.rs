//! Unicode entry names inside jar archives must unpack and scan.

use crate::support::split_chunk_results;
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
    zip.write_all(
        b"GITHUB_TOKEN=ghp_unicodeJarEntryTest000000000001
",
    )
    .expect("write");
    zip.finish().expect("finish");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid unicode jar entry should not emit SourceError rows: {errors:?}"
    );
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("ghp_unicodeJarEntryTest")),
        "unicode jar entry must be scanned; got {chunks:?}"
    );
    assert!(
        chunks.iter().any(|chunk| chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|path| path.contains("i18n.jar//配置/秘密.env"))),
        "unicode jar entry path must preserve archive and entry names, got {chunks:?}"
    );
}
