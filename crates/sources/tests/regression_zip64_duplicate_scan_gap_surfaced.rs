//! Regression: a zip whose end-of-central-directory carries a zip64 sentinel
//! makes the duplicate-entry detector bail — it explicitly does not model zip64
//! central directories. That bail used to be swallowed by an
//! `if let Ok(Some(..))` in `extract_zip_archive`, so the archive was silently
//! handed to the standard parser (which surfaces only one entry per name); any
//! duplicated/shadow central-directory entry an attacker hid a secret in
//! vanished with no trace. The degrade must now be recorded as a partial-coverage
//! gap so the recall loss is visible (Law 10), not silent.

use keyhog_core::Source;
use keyhog_sources::{reset_skipped_over_max_size, skip_counts, FilesystemSource};

#[test]
fn zip64_eocd_sentinel_records_duplicate_scan_unavailable_gap() {
    // Process-global counters; this standalone test binary runs only this test,
    // so the reset+read is race-free. `reset_skipped_over_max_size` zeroes every
    // skip counter (Law 3 alias).
    reset_skipped_over_max_size();
    let before = skip_counts().archive_duplicate_scan_unavailable;

    let dir = tempfile::tempdir().expect("tempdir");
    let zip_path = dir.path().join("z64.zip");
    std::fs::write(
        &zip_path,
        zip_with_zip64_eocd_sentinel(
            "secret.txt",
            b"SLACK=xoxb-111111111111-111111111111-aaaaaaaaaaaaaaaaaaaaaaaa\n",
        ),
    )
    .expect("write zip64-sentinel archive");

    // Drive the real filesystem extraction path; we only care that the degrade
    // is recorded, not whether the standard parser then succeeds.
    let _ = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .filter_map(Result::ok)
        .count();

    let after = skip_counts().archive_duplicate_scan_unavailable;
    assert!(
        after > before,
        "a zip64-sentinel archive must record an archive_duplicate_scan_unavailable \
         partial-coverage gap instead of silently degrading; before={before} after={after}"
    );
}

/// Build a minimal stored single-entry zip, then set the classic EOCD's
/// total-entry-count field to the zip64 sentinel `0xFFFF`. `read_central_zip_entries`
/// reads that field at `eocd + 10` and returns "zip64 central directory is not
/// handled by duplicate fallback" — the exact `Err` whose former silent swallow
/// this test guards against.
fn zip_with_zip64_eocd_sentinel(name: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let name_bytes = name.as_bytes();
    let size = u32::try_from(data.len()).expect("small data");
    let name_len = u16::try_from(name_bytes.len()).expect("short name");
    let crc = crc32(data);

    // Local file header.
    let local_offset = u32::try_from(out.len()).expect("small offset");
    write_u32(&mut out, 0x0403_4b50);
    write_u16(&mut out, 20); // version needed
    write_u16(&mut out, 0); // flags
    write_u16(&mut out, 0); // method: stored
    write_u16(&mut out, 0); // mod time
    write_u16(&mut out, 0); // mod date
    write_u32(&mut out, crc);
    write_u32(&mut out, size); // compressed
    write_u32(&mut out, size); // uncompressed
    write_u16(&mut out, name_len);
    write_u16(&mut out, 0); // extra len
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(data);

    // Central directory header.
    let central_offset = u32::try_from(out.len()).expect("small offset");
    write_u32(&mut out, 0x0201_4b50);
    write_u16(&mut out, 20); // version made by
    write_u16(&mut out, 20); // version needed
    write_u16(&mut out, 0); // flags
    write_u16(&mut out, 0); // method
    write_u16(&mut out, 0); // mod time
    write_u16(&mut out, 0); // mod date
    write_u32(&mut out, crc);
    write_u32(&mut out, size);
    write_u32(&mut out, size);
    write_u16(&mut out, name_len);
    write_u16(&mut out, 0); // extra len
    write_u16(&mut out, 0); // comment len
    write_u16(&mut out, 0); // disk start
    write_u16(&mut out, 0); // internal attrs
    write_u32(&mut out, 0); // external attrs
    write_u32(&mut out, local_offset);
    out.extend_from_slice(name_bytes);

    let central_size = u32::try_from(out.len())
        .expect("small zip")
        .checked_sub(central_offset)
        .expect("central size");

    // Classic end-of-central-directory record with the zip64 entry-count sentinel.
    write_u32(&mut out, 0x0605_4b50);
    write_u16(&mut out, 0); // disk number
    write_u16(&mut out, 0); // disk with central dir
    write_u16(&mut out, 0xFFFF); // entries on this disk (zip64 sentinel)
    write_u16(&mut out, 0xFFFF); // total entries (zip64 sentinel) — read at eocd+10
    write_u32(&mut out, central_size);
    write_u32(&mut out, central_offset);
    write_u16(&mut out, 0); // comment length
    out
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
