//! Duplicate-ZIP fallback must bound attacker-declared allocation sizes by the
//! actual file length before allocating central-directory or entry data buffers.

use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::io::Write;

#[test]
fn oversized_central_directory_size_is_rejected_not_allocated() {
    let mut eocd = Vec::new();
    eocd.extend_from_slice(b"PK\x05\x06");
    write_u16(&mut eocd, 0);
    write_u16(&mut eocd, 0);
    write_u16(&mut eocd, 1);
    write_u16(&mut eocd, 1);
    write_u32(&mut eocd, 1_000_000);
    write_u32(&mut eocd, 0);
    write_u16(&mut eocd, 0);
    assert_eq!(eocd.len(), 22);

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("oversized_central.zip");
    std::fs::File::create(&path)
        .expect("create")
        .write_all(&eocd)
        .expect("write");

    let err = TestApi
        .duplicate_zip_central_entries_error(&path)
        .expect("oversized central directory must return the rejection error");
    assert!(
        err.contains("central directory past the end of the file"),
        "expected central-directory bounds rejection before allocation, got: {err}"
    );
}

#[test]
fn oversized_local_entry_compressed_size_is_rejected_not_allocated() {
    let mut local = Vec::new();
    write_u32(&mut local, 0x0403_4b50);
    write_u16(&mut local, 20);
    write_u16(&mut local, 0);
    write_u16(&mut local, 0);
    write_u16(&mut local, 0);
    write_u16(&mut local, 0);
    write_u32(&mut local, 0);
    write_u32(&mut local, 0);
    write_u32(&mut local, 0);
    write_u16(&mut local, 0);
    write_u16(&mut local, 0);
    assert_eq!(local.len(), 30);

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("oversized_entry.zip");
    std::fs::File::create(&path)
        .expect("create")
        .write_all(&local)
        .expect("write");

    let err = TestApi
        .duplicate_zip_local_entry_data_error(&path, 1_000_000)
        .expect("oversized local entry data must return the rejection error");
    assert!(
        err.contains("compressed data past the end of the file"),
        "expected local-entry bounds rejection before allocation, got: {err}"
    );
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
