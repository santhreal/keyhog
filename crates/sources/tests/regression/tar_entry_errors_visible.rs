use std::io::Write as _;

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};

use crate::support::split_chunk_results;

fn write_tar_with_over_cap_entry(root: &std::path::Path) -> std::path::PathBuf {
    let tar_path = root.join("fixtures.tgz");
    let mut tar_bytes = Vec::new();
    let mut tar = tar::Builder::new(&mut tar_bytes);

    let safe = b"SAFE=AKIAQYLPMN5HFIQR7XYA\n";
    let mut safe_header = tar::Header::new_gnu();
    safe_header.set_path("safe.env").expect("safe path");
    safe_header.set_size(safe.len() as u64);
    safe_header.set_cksum();
    tar.append(&safe_header, &safe[..]).expect("append safe");

    let oversized = vec![b'X'; 4096];
    let mut oversized_header = tar::Header::new_gnu();
    oversized_header
        .set_path("too-large.env")
        .expect("oversized path");
    oversized_header.set_size(oversized.len() as u64);
    oversized_header.set_cksum();
    tar.append(&oversized_header, &oversized[..])
        .expect("append oversized");

    tar.finish().expect("finish tar");
    drop(tar);

    let file = std::fs::File::create(&tar_path).expect("create tgz");
    let mut gzip = flate2::write::GzEncoder::new(file, flate2::Compression::best());
    gzip.write_all(&tar_bytes).expect("write tgz");
    gzip.finish().expect("finish tgz");
    tar_path
}

fn write_tar_with_symlink_entry(root: &std::path::Path) -> std::path::PathBuf {
    let tar_path = root.join("links.tgz");
    let mut tar_bytes = Vec::new();
    let mut tar = tar::Builder::new(&mut tar_bytes);

    let mut link_header = tar::Header::new_gnu();
    link_header.set_entry_type(tar::EntryType::Symlink);
    link_header.set_size(0);
    link_header
        .set_link_name("target.env")
        .expect("symlink target");
    link_header.set_cksum();
    tar.append_data(&mut link_header, "link.env", std::io::empty())
        .expect("append symlink");

    let safe = b"SAFE=AKIAQYLPMN5HFIQR7XYA\n";
    let mut safe_header = tar::Header::new_gnu();
    safe_header.set_path("safe.env").expect("safe path");
    safe_header.set_size(safe.len() as u64);
    safe_header.set_cksum();
    tar.append(&safe_header, &safe[..]).expect("append safe");

    tar.finish().expect("finish tar");
    drop(tar);

    let file = std::fs::File::create(&tar_path).expect("create tgz");
    let mut gzip = flate2::write::GzEncoder::new(file, flate2::Compression::best());
    gzip.write_all(&tar_bytes).expect("write tgz");
    gzip.finish().expect("finish tgz");
    tar_path
}

fn write_tar_with_malformed_size_entry(root: &std::path::Path) -> std::path::PathBuf {
    let tar_path = root.join("malformed-size.tgz");
    let mut tar_bytes = vec![0u8; 1024];
    let header = &mut tar_bytes[..512];
    header[..10].copy_from_slice(b"broken.env");
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(b"not-octal\0\0\0");
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    let checksum_field = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(checksum_field.as_bytes());

    let file = std::fs::File::create(&tar_path).expect("create tgz");
    let mut gzip = flate2::write::GzEncoder::new(file, flate2::Compression::best());
    gzip.write_all(&tar_bytes).expect("write tgz");
    gzip.finish().expect("finish tgz");
    tar_path
}

#[test]
fn tar_over_cap_entry_emits_source_error_and_keeps_safe_sibling() {
    let _guard = TestApi.skip_counter_guard();
    let dir = tempfile::tempdir().expect("tempdir");
    let _tar = write_tar_with_over_cap_entry(dir.path());

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(2048);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.as_str().contains("AKIAQYLPMN5HFIQR7XYA")),
        "safe tar sibling must still be scanned; chunks={chunks:?}"
    );
    assert_eq!(
        errors.len(),
        1,
        "the over-cap tar entry must emit exactly one SourceError row"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("failed to scan tar entry")
            && error.contains("fixtures.tgz//too-large.env")
            && error.contains("entry was not scanned"),
        "tar SourceError must identify the unscanned entry and reason, got {error:?}"
    );
    assert_eq!(
        skip_counts().over_max_size,
        1,
        "the over-cap tar entry must also count as a coverage gap"
    );
}

#[test]
fn tar_malformed_size_header_emits_source_error_and_counts_unreadable() {
    let _guard = TestApi.skip_counter_guard();
    let dir = tempfile::tempdir().expect("tempdir");
    let _tar = write_tar_with_malformed_size_entry(dir.path());

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(2048);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        chunks.is_empty(),
        "malformed-size tar entry body must not be treated as clean scanned content; chunks={chunks:?}"
    );
    assert_eq!(
        errors.len(),
        1,
        "the malformed tar size header must emit exactly one SourceError row"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("failed to scan tar entry")
            && error.contains("malformed-size.tgz//<tar-entry>")
            && error.contains("cannot read tar entry header")
            && error.contains("not-octal"),
        "tar SourceError must identify the malformed-size entry gap, got {error:?}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "the malformed tar size header must count as an unreadable coverage gap"
    );
}

#[test]
fn tar_symlink_entry_emits_source_error_and_keeps_safe_sibling() {
    let _guard = TestApi.skip_counter_guard();
    let dir = tempfile::tempdir().expect("tempdir");
    let _tar = write_tar_with_symlink_entry(dir.path());

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(2048);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.as_str().contains("AKIAQYLPMN5HFIQR7XYA")),
        "safe tar sibling must still be scanned; chunks={chunks:?}"
    );
    assert!(
        !chunks
            .iter()
            .any(|chunk| chunk.data.to_string().contains("target.env")),
        "tar symlink payload must not be scanned as file content; chunks={chunks:?}"
    );
    assert_eq!(
        errors.len(),
        1,
        "the tar symlink entry must emit exactly one SourceError row"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("failed to scan tar entry")
            && error.contains("links.tgz//link.env")
            && error.contains("non-regular tar entry type")
            && error.contains("entry was not scanned"),
        "tar SourceError must identify the unscanned symlink entry and reason, got {error:?}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "the tar symlink entry must count as unreadable coverage gap"
    );
}
