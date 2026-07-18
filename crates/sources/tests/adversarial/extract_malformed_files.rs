//! Adversarial survival tests for `crates/sources/src/filesystem/extract.rs`.
//!
//! Each extractor must refuse corrupted, empty, or truncated binary inputs with
//! a counted error or skip, and must never panic. HAR and PDF are special:
//! without their magic they fall back to the normal text/binary scanning path,
//! so the oracle for those is "survives and does not panic".

use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::io::Write;

fn tmp_file_with(extension: &str, bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf, u64) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(format!("fixture.{extension}"));
    let mut file = std::fs::File::create(&path).expect("create fixture");
    file.write_all(bytes).expect("write fixture");
    let size = file.metadata().expect("metadata").len();
    (dir, path, size)
}

fn rows_for(extension: &str, bytes: &[u8]) -> Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>> {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let (_dir, path, size) = tmp_file_with(extension, bytes);
    TestApi.process_entry_with_recorded_size(path, size, 1024 * 1024)
}

fn assert_no_panic(extension: &str, bytes: &[u8]) {
    // The mere act of calling the extractor and getting a Vec back is the
    // survival assertion. A panic aborts the test before this point.
    let _rows = rows_for(extension, bytes);
}

fn assert_no_success_chunks(extension: &str, bytes: &[u8]) {
    let rows = rows_for(extension, bytes);
    let successes: Vec<_> = rows.iter().filter(|r| r.is_ok()).collect();
    assert!(
        successes.is_empty(),
        "{extension} with malformed/empty bytes must not yield successful chunks; got {successes:?}"
    );
}

// --- binary archive formats: malformed/empty must not produce chunks --------

#[test]
fn empty_rar_survives_as_unreadable() {
    assert_no_success_chunks("rar", b"");
}

#[test]
fn truncated_rar_magic_survives_as_unreadable() {
    assert_no_success_chunks("rar", b"Rar!");
}

#[test]
fn empty_seven_zip_survives_as_unreadable() {
    assert_no_success_chunks("7z", b"");
}

#[test]
fn seven_zip_with_bad_magic_survives_as_unreadable() {
    assert_no_success_chunks("7z", b"7z\x00\x00\x00\x00");
}

#[test]
fn empty_gzip_survives_as_unreadable() {
    assert_no_success_chunks("gz", b"");
}

#[test]
fn gzip_with_bad_magic_survives_as_unreadable() {
    assert_no_success_chunks("gz", b"\x1f\x8b");
}

#[test]
fn empty_bz2_survives_as_unreadable() {
    assert_no_success_chunks("bz2", b"");
}

#[test]
fn bz2_with_bad_digit_survives_as_unreadable() {
    assert_no_success_chunks("bz2", b"BZh0");
}

#[test]
fn empty_tar_survives_as_unreadable() {
    assert_no_success_chunks("tar", b"");
}

#[test]
fn empty_tex_package_survives_as_unreadable() {
    assert_no_success_chunks("tex", b"");
}

#[test]
fn empty_image_file_survives_as_unreadable_or_binary_without_strings() {
    assert_no_success_chunks("png", b"");
    assert_no_success_chunks("jpg", b"");
    assert_no_success_chunks("gif", b"");
}

// --- HAR and PDF: no magic -> fallback scan, so only assert no panic --------

#[test]
fn empty_pdf_survives_and_does_not_panic() {
    assert_no_panic("pdf", b"");
}

#[test]
fn pdf_without_header_survives_and_does_not_panic() {
    assert_no_panic("pdf", b"this is not a pdf");
}

#[test]
fn empty_har_survives_and_does_not_panic() {
    assert_no_panic("har", b"");
}

#[test]
fn har_with_invalid_json_survives_and_does_not_panic() {
    assert_no_panic("har", b"{not json}");
}
