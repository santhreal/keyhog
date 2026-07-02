//! Regression coverage for the Hyperscan serialized-cache header contract.
//!
//! These tests lock the exact byte constants and the read/write round-trip so that
//! the read-side validator (`hyperscan_cache_header_is_valid`) and the write-side
//! emitter (`write_hyperscan_cache_header`) cannot silently drift apart.

use keyhog_core::{
    hyperscan_cache_header_is_valid, write_hyperscan_cache_header, HYPERSCAN_CACHE_FILE_BYTES,
    HYPERSCAN_CACHE_HEADER_LEN, HYPERSCAN_CACHE_MAGIC, HYPERSCAN_CACHE_VERSION,
};

/// The documented byte constants have their exact wire values.
#[test]
fn constants_have_exact_documented_values() {
    assert_eq!(HYPERSCAN_CACHE_MAGIC, b"KHHS");
    assert_eq!(*HYPERSCAN_CACHE_MAGIC, [0x4B, 0x48, 0x48, 0x53]);
    assert_eq!(HYPERSCAN_CACHE_VERSION, 2_u32);
    assert_eq!(HYPERSCAN_CACHE_HEADER_LEN, 8_usize);
    assert_eq!(HYPERSCAN_CACHE_FILE_BYTES, 128 * 1024 * 1024);
    assert_eq!(HYPERSCAN_CACHE_FILE_BYTES, 134_217_728_u64);
}

/// The header length equals magic (4 bytes) plus a little-endian u32 version (4 bytes).
#[test]
fn header_len_is_magic_plus_version_width() {
    assert_eq!(
        HYPERSCAN_CACHE_HEADER_LEN,
        HYPERSCAN_CACHE_MAGIC.len() + std::mem::size_of::<u32>()
    );
    assert_eq!(HYPERSCAN_CACHE_HEADER_LEN, 8);
}

/// `write_hyperscan_cache_header` produces exactly the expected 8 bytes.
#[test]
fn write_emits_exact_header_bytes() {
    let mut out: Vec<u8> = Vec::new();
    write_hyperscan_cache_header(&mut out);
    assert_eq!(out.len(), 8);
    // KHHS then version 2 as little-endian u32.
    assert_eq!(out, vec![0x4B, 0x48, 0x48, 0x53, 0x02, 0x00, 0x00, 0x00]);
}

/// A freshly written header validates true.
#[test]
fn written_header_round_trips_valid() {
    let mut out: Vec<u8> = Vec::new();
    write_hyperscan_cache_header(&mut out);
    assert!(hyperscan_cache_header_is_valid(&out));
    assert_eq!(hyperscan_cache_header_is_valid(&out), true);
}

/// `write` appends the header rather than clobbering existing payload bytes.
#[test]
fn write_appends_after_existing_bytes() {
    let mut out: Vec<u8> = vec![0xAA, 0xBB];
    write_hyperscan_cache_header(&mut out);
    assert_eq!(out.len(), 10);
    assert_eq!(&out[..2], &[0xAA, 0xBB]);
    assert_eq!(&out[2..], &[0x4B, 0x48, 0x48, 0x53, 0x02, 0x00, 0x00, 0x00]);
    // The appended header slice alone still validates.
    let header_tail = out[2..].to_vec();
    assert_eq!(hyperscan_cache_header_is_valid(&header_tail), true);
}

/// A header with a corrupted magic byte is rejected.
#[test]
fn wrong_magic_is_rejected() {
    let bad: [u8; 8] = [0x4B, 0x48, 0x48, 0x54, 0x02, 0x00, 0x00, 0x00]; // 'T' not 'S'
    assert_eq!(hyperscan_cache_header_is_valid(&bad), false);
}

/// A header whose magic is entirely different is rejected.
#[test]
fn foreign_magic_is_rejected() {
    let bad: [u8; 8] = [b'X', b'X', b'X', b'X', 0x02, 0x00, 0x00, 0x00];
    assert_eq!(hyperscan_cache_header_is_valid(&bad), false);
}

/// A header with the wrong version (older v1) is rejected even with correct magic.
#[test]
fn wrong_version_v1_is_rejected() {
    let bad: [u8; 8] = [0x4B, 0x48, 0x48, 0x53, 0x01, 0x00, 0x00, 0x00];
    assert_eq!(hyperscan_cache_header_is_valid(&bad), false);
}

/// A header with a future version (v3) is rejected.
#[test]
fn future_version_v3_is_rejected() {
    let bad: [u8; 8] = [0x4B, 0x48, 0x48, 0x53, 0x03, 0x00, 0x00, 0x00];
    assert_eq!(hyperscan_cache_header_is_valid(&bad), false);
}

/// Version bytes in big-endian order (0x02 in the high byte) do not validate,
/// proving the reader uses little-endian decoding.
#[test]
fn big_endian_version_is_rejected() {
    let bad: [u8; 8] = [0x4B, 0x48, 0x48, 0x53, 0x00, 0x00, 0x00, 0x02];
    // This decodes little-endian to version 0x02000000, not 2.
    assert_eq!(hyperscan_cache_header_is_valid(&bad), false);
}

/// A header truncated below the required length is rejected.
#[test]
fn truncated_header_is_rejected() {
    let full: [u8; 8] = [0x4B, 0x48, 0x48, 0x53, 0x02, 0x00, 0x00, 0x00];
    for len in 0..HYPERSCAN_CACHE_HEADER_LEN {
        let slice = &full[..len];
        assert_eq!(
            hyperscan_cache_header_is_valid(slice),
            false,
            "length {len} must be rejected"
        );
    }
}

/// A header one byte too long is rejected (exact length required).
#[test]
fn overlong_header_is_rejected() {
    let over: [u8; 9] = [0x4B, 0x48, 0x48, 0x53, 0x02, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(over.len(), HYPERSCAN_CACHE_HEADER_LEN + 1);
    assert_eq!(hyperscan_cache_header_is_valid(&over), false);
}

/// An empty slice is rejected.
#[test]
fn empty_header_is_rejected() {
    let empty: [u8; 0] = [];
    assert_eq!(hyperscan_cache_header_is_valid(&empty), false);
}

/// An all-zero buffer of the correct length is rejected (no magic).
#[test]
fn all_zero_header_is_rejected() {
    let zeros = [0_u8; 8];
    assert_eq!(hyperscan_cache_header_is_valid(&zeros), false);
}

/// The exact valid header literal validates, independent of the writer.
#[test]
fn hand_built_valid_header_accepts() {
    let good: [u8; 8] = [0x4B, 0x48, 0x48, 0x53, 0x02, 0x00, 0x00, 0x00];
    assert_eq!(hyperscan_cache_header_is_valid(&good), true);
}
