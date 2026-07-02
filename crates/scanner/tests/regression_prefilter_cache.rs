//! Regression coverage for the shared Hyperscan serialized-cache header contract.
//!
//! These tests pin the exact on-disk header bytes that the SIMD prefilter backend
//! writes ahead of every serialized Hyperscan shard and validates before trusting a
//! cached shard. The header owner lives in `keyhog_core`; the scanner consumes it via
//! the public `keyhog_core::{write_hyperscan_cache_header, hyperscan_cache_header_is_valid}`
//! API plus the `HYPERSCAN_CACHE_*` constants. If any byte, order, or bound drifts, a
//! cold cache is silently accepted or a valid cache is silently rejected, so each
//! assertion below is a concrete expected value.

/// The canonical 8-byte header a fresh write must emit: magic `KHHS` then the
/// little-endian version (`2` -> `02 00 00 00`).
const EXPECTED_HEADER: [u8; 8] = [b'K', b'H', b'H', b'S', 0x02, 0x00, 0x00, 0x00];

#[test]
fn magic_constant_is_exact_bytes() {
    assert_eq!(keyhog_core::HYPERSCAN_CACHE_MAGIC, b"KHHS");
    assert_eq!(
        keyhog_core::HYPERSCAN_CACHE_MAGIC,
        &[0x4B, 0x48, 0x48, 0x53]
    );
}

#[test]
fn version_constant_is_two() {
    assert_eq!(keyhog_core::HYPERSCAN_CACHE_VERSION, 2_u32);
}

#[test]
fn header_len_constant_is_eight() {
    assert_eq!(keyhog_core::HYPERSCAN_CACHE_HEADER_LEN, 8_usize);
    // The header is exactly magic (4 bytes) + a little-endian u32 version (4 bytes).
    assert_eq!(
        keyhog_core::HYPERSCAN_CACHE_HEADER_LEN,
        keyhog_core::HYPERSCAN_CACHE_MAGIC.len() + core::mem::size_of::<u32>()
    );
}

#[test]
fn file_bytes_cap_is_128_mib() {
    assert_eq!(keyhog_core::HYPERSCAN_CACHE_FILE_BYTES, 134_217_728_u64);
    assert_eq!(keyhog_core::HYPERSCAN_CACHE_FILE_BYTES, 128 * 1024 * 1024);
}

#[test]
fn write_header_emits_exact_eight_bytes() {
    let mut out = Vec::new();
    keyhog_core::write_hyperscan_cache_header(&mut out);
    assert_eq!(out.len(), 8);
    assert_eq!(out.as_slice(), &EXPECTED_HEADER);
    // Magic occupies the first four bytes in order.
    assert_eq!(&out[..4], b"KHHS");
    // Version is little-endian in the trailing four bytes.
    assert_eq!(&out[4..8], &[0x02, 0x00, 0x00, 0x00]);
    assert_eq!(
        u32::from_le_bytes([out[4], out[5], out[6], out[7]]),
        keyhog_core::HYPERSCAN_CACHE_VERSION
    );
}

#[test]
fn write_then_validate_round_trips_true() {
    let mut out = Vec::new();
    keyhog_core::write_hyperscan_cache_header(&mut out);
    assert!(keyhog_core::hyperscan_cache_header_is_valid(&out));
}

#[test]
fn write_appends_and_preserves_existing_prefix() {
    // The writer must extend, never overwrite: a serialized shard body already sits in
    // the buffer and the header is appended after it in the backend's persist path.
    let mut out = vec![0xAA, 0xBB, 0xCC];
    keyhog_core::write_hyperscan_cache_header(&mut out);
    assert_eq!(out.len(), 11);
    assert_eq!(&out[..3], &[0xAA, 0xBB, 0xCC]);
    assert_eq!(&out[3..], &EXPECTED_HEADER);
    // The appended 8-byte tail is itself a valid header.
    assert!(keyhog_core::hyperscan_cache_header_is_valid(&out[3..]));
}

#[test]
fn exact_valid_header_validates_true() {
    assert!(keyhog_core::hyperscan_cache_header_is_valid(
        &EXPECTED_HEADER
    ));
}

#[test]
fn corrupted_magic_validates_false() {
    // Flip the first magic byte 'K' -> 'X'; every other byte stays canonical.
    let mut header = EXPECTED_HEADER;
    header[0] = b'X';
    assert!(!keyhog_core::hyperscan_cache_header_is_valid(&header));

    // Flip only the last magic byte 'S' -> 's'.
    let mut header2 = EXPECTED_HEADER;
    header2[3] = b's';
    assert!(!keyhog_core::hyperscan_cache_header_is_valid(&header2));
}

#[test]
fn wrong_version_validates_false() {
    // Version 1 (the predecessor) must be rejected.
    let mut v1 = EXPECTED_HEADER;
    v1[4] = 0x01;
    assert!(!keyhog_core::hyperscan_cache_header_is_valid(&v1));

    // Version 3 (a hypothetical successor) must be rejected.
    let mut v3 = EXPECTED_HEADER;
    v3[4] = 0x03;
    assert!(!keyhog_core::hyperscan_cache_header_is_valid(&v3));

    // Version 0 must be rejected.
    let mut v0 = EXPECTED_HEADER;
    v0[4] = 0x00;
    assert!(!keyhog_core::hyperscan_cache_header_is_valid(&v0));
}

#[test]
fn high_byte_version_flip_validates_false() {
    // A big-endian misread of version 2 would be 0x02000000 == 33_554_432; ensure a
    // high-order byte set (i.e. version != 2 in the actual little-endian decode) fails.
    let mut header = EXPECTED_HEADER;
    header[7] = 0x02; // now decodes to 0x02000002, not 2
    assert!(!keyhog_core::hyperscan_cache_header_is_valid(&header));
    assert_ne!(
        u32::from_le_bytes([header[4], header[5], header[6], header[7]]),
        keyhog_core::HYPERSCAN_CACHE_VERSION
    );
}

#[test]
fn short_header_validates_false() {
    // Seven bytes: one short of the required length.
    assert!(!keyhog_core::hyperscan_cache_header_is_valid(
        &EXPECTED_HEADER[..7]
    ));
    // Empty slice.
    assert!(!keyhog_core::hyperscan_cache_header_is_valid(&[]));
    // Just the 4 magic bytes with no version.
    assert!(!keyhog_core::hyperscan_cache_header_is_valid(b"KHHS"));
}

#[test]
fn overlong_header_validates_false() {
    // Nine bytes: a valid 8-byte header with one trailing byte. The validator requires
    // an exact-length header, so trailing shard payload bytes must not be included.
    let mut nine = EXPECTED_HEADER.to_vec();
    nine.push(0x00);
    assert_eq!(nine.len(), 9);
    assert!(!keyhog_core::hyperscan_cache_header_is_valid(&nine));
}

#[test]
fn empty_body_write_and_validate_by_header_len_slice() {
    // Mirrors the backend read path: write the header, then validate exactly
    // HYPERSCAN_CACHE_HEADER_LEN leading bytes of a larger buffer.
    let mut data = Vec::new();
    keyhog_core::write_hyperscan_cache_header(&mut data);
    data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // fake serialized shard tail
    assert_eq!(data.len(), 12);
    let header_len = keyhog_core::HYPERSCAN_CACHE_HEADER_LEN;
    assert!(data.len() > header_len);
    assert!(keyhog_core::hyperscan_cache_header_is_valid(
        &data[..header_len]
    ));
    // The full buffer (header + body) is NOT a bare header and must not validate.
    assert!(!keyhog_core::hyperscan_cache_header_is_valid(&data));
}

#[test]
fn all_zero_header_validates_false() {
    // A freshly zero-initialized buffer (e.g. a truncated/never-written file) must be
    // rejected: neither magic nor version matches.
    let zeros = [0_u8; 8];
    assert!(!keyhog_core::hyperscan_cache_header_is_valid(&zeros));
}
