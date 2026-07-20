//! ZIP entries that represent symlinks/devices are refused visibly.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};
use std::io::Cursor;
use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn zip_symlink_entry_emits_source_error() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let zip_path = dir.path().join("special.zip");
    let cursor = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(cursor);
    let symlink_opts = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o120777);
    zip.start_file("link.env", symlink_opts)
        .expect("start symlink entry");
    zip.write_all(b"target.env").expect("write symlink target");

    let safe_opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("safe.env", safe_opts)
        .expect("start safe entry");
    zip.write_all(b"SAFE=still_scanned\n")
        .expect("write safe entry");
    let mut zip_bytes = zip.finish().expect("finish zip").into_inner();
    mark_central_entry_as_unix_symlink(&mut zip_bytes, b"link.env");
    std::fs::write(&zip_path, zip_bytes).expect("write patched zip");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let bodies: Vec<_> = chunks
        .iter()
        .map(|chunk| chunk.data.as_str().to_owned())
        .collect();

    assert!(
        bodies
            .iter()
            .any(|body| body.contains("SAFE=still_scanned")),
        "safe sibling entry must still be scanned; bodies={bodies:?}"
    );
    assert!(
        !bodies.iter().any(|body| body.contains("target.env")),
        "symlink entry payload must not be scanned as a regular file; bodies={bodies:?}"
    );
    assert_eq!(
        errors.len(),
        1,
        "refused ZIP symlink entry must emit one SourceError"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("special.zip//link.env")
            && error.contains("special file type")
            && error.contains("entry was not scanned"),
        "special ZIP entry error must name the skipped entry and reason, got {error}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "refused ZIP symlink entry must count one unreadable coverage gap"
    );
}

fn mark_central_entry_as_unix_symlink(zip_bytes: &mut [u8], name: &[u8]) {
    let mut offset = 0usize;
    while offset < zip_bytes.len() {
        let Some(relative) = zip_bytes[offset..]
            .windows(4)
            .position(|window| window == b"PK\x01\x02")
        else {
            break;
        };
        let central = offset + relative;
        if central + 46 > zip_bytes.len() {
            break;
        }
        let name_len =
            u16::from_le_bytes([zip_bytes[central + 28], zip_bytes[central + 29]]) as usize;
        let extra_len =
            u16::from_le_bytes([zip_bytes[central + 30], zip_bytes[central + 31]]) as usize;
        let comment_len =
            u16::from_le_bytes([zip_bytes[central + 32], zip_bytes[central + 33]]) as usize;
        let name_start = central + 46;
        let name_end = name_start.saturating_add(name_len);
        if name_end <= zip_bytes.len() && &zip_bytes[name_start..name_end] == name {
            zip_bytes[central + 5] = 3;
            let external_attrs = (0o120777_u32 << 16).to_le_bytes();
            zip_bytes[central + 38..central + 42].copy_from_slice(&external_attrs);
            return;
        }
        offset = name_end
            .saturating_add(extra_len)
            .saturating_add(comment_len);
    }
    panic!(
        "test fixture did not contain central-directory entry {}",
        String::from_utf8_lossy(name)
    );
}
