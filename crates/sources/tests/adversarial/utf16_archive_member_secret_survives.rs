//! A UTF-16 file packed inside a gz / tar.gz archive must still surface its
//! ASCII secrets. REGRESSION: the archive/compressed extractors decoded each
//! entry's bytes with raw `String::from_utf8`. The `FF FE` UTF-16 BOM made that
//! decode fail, and the NUL-separated ASCII (`g\0h\0p\0…`) could not reform an
//! 8-char printable run, so the secret vanished as a silent false "clean". All
//! extractors now share the canonical UTF-16-aware
//! `decode_text_file_owned_or_bytes` decoder via `chunk_from_extracted_entry`,
//! keeping archive recall in parity with the plain filesystem read path.

use crate::support::split_chunk_results;
use flate2::write::GzEncoder;
use flate2::Compression;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use std::io::Write;

/// Encode `s` as UTF-16LE bytes with a leading BOM (`FF FE`) — the exact shape a
/// Windows/PowerShell/.NET tool writes and the old `String::from_utf8` decode
/// could not handle.
fn utf16le_with_bom(s: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// The NUL-interleaved form a raw-byte decode would have left the marker in —
/// asserting its ABSENCE proves the canonical decoder ran.
fn nul_interleaved(s: &str) -> String {
    s.chars().flat_map(|c| [c, '\u{0}']).collect()
}

#[test]
fn gz_member_utf16_secret_survives() {
    // Single-member gzip of a UTF-16LE file: exercises the whole-stream decode
    // (compressed.rs -> chunk_from_extracted_entry, "filesystem/compressed").
    let marker = "AWS_SECRET=utf16_gz_member_marker";
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transcript.txt.gz");
    let file = File::create(&path).expect("create");
    let mut enc = GzEncoder::new(file, Compression::default());
    enc.write_all(&utf16le_with_bom(&format!("{marker}\r\n")))
        .expect("write");
    enc.finish().expect("finish");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid single-member gz should not emit SourceError rows: {errors:?}"
    );
    assert!(
        chunks.iter().any(|c| c.data.contains(marker)),
        "UTF-16 gz member secret must survive de-interleaved; got {chunks:?}"
    );
    let interleaved = nul_interleaved(marker);
    assert!(
        chunks.iter().all(|c| !c.data.contains(&interleaved)),
        "secret must not appear NUL-interleaved (would mean the raw from_utf8 path ran); got {chunks:?}"
    );
}

#[test]
fn targz_member_utf16_secret_survives() {
    // A .tar.gz whose member is a UTF-16LE file: exercises the per-tar-entry
    // decode (emit_tar_entries -> chunk_from_extracted_entry,
    // "filesystem/archive").
    let marker = "DB_PASSWORD=utf16_tar_member_marker";
    let member = utf16le_with_bom(&format!("{marker}\r\n"));

    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path("config.txt").expect("set member path");
    header.set_size(member.len() as u64);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder.append(&header, member.as_slice()).expect("append");
    builder.finish().expect("finish tar");
    let tar_bytes = builder.into_inner().expect("tar bytes");

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bundle.tar.gz");
    let file = File::create(&path).expect("create");
    let mut enc = GzEncoder::new(file, Compression::default());
    enc.write_all(&tar_bytes).expect("write");
    enc.finish().expect("finish");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid tar.gz should not emit SourceError rows: {errors:?}"
    );
    assert!(
        chunks.iter().any(|c| c.data.contains(marker)),
        "UTF-16 tar.gz member secret must survive de-interleaved; got {chunks:?}"
    );
    let interleaved = nul_interleaved(marker);
    assert!(
        chunks.iter().all(|c| !c.data.contains(&interleaved)),
        "secret must not appear NUL-interleaved; got {chunks:?}"
    );
}
