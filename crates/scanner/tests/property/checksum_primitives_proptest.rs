//! Checksum-primitive correctness (`crates/scanner/src/checksum/github.rs`,
//! re-exported through `checksum::{standard_crc32, base62_encode_u32,
//! crc32_base62_suffix}`).
//!
//! These two primitives are load-bearing for EVERY CRC32-checksummed token
//! validator (GitHub classic/fine-grained/OAuth, npm, …): a wrong CRC or a wrong
//! base62 encoding silently flips real tokens to `Invalid` (recall loss) or
//! fabricated ones to `Valid` (precision loss). They are pure and
//! detection-semantics-neutral, so they get exact known-answer vectors plus
//! whole-`u32` round-trip / alphabet / padding invariants — the algorithm itself
//! is pinned, independent of any detector policy.

use keyhog_scanner::testing::checksum::{base62_encode_u32, crc32_base62_suffix, standard_crc32};
use proptest::prelude::*;

const BASE62_DIGITS: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Independent reference base62 decoder (big-endian, same alphabet) so the
/// round-trip proves `base62_encode_u32` is the exact inverse — not merely
/// self-consistent.
fn base62_decode(s: &str) -> u64 {
    let mut v: u64 = 0;
    for ch in s.bytes() {
        let d = BASE62_DIGITS
            .iter()
            .position(|&c| c == ch)
            .expect("encoded output must only contain base62 alphabet chars")
            as u64;
        v = v * 62 + d;
    }
    v
}

// ── CRC-32/ISO-HDLC known-answer vectors ─────────────────────────────────────

#[test]
fn crc32_matches_standard_check_vectors() {
    // Canonical CRC-32 (poly 0xEDB88320, init/xorout 0xFFFFFFFF) reference values.
    assert_eq!(standard_crc32(b""), 0x0000_0000, "empty input");
    assert_eq!(
        standard_crc32(b"123456789"),
        0xCBF4_3926,
        "the canonical CRC-32 check value"
    );
    assert_eq!(
        standard_crc32(b"The quick brown fox jumps over the lazy dog"),
        0x414F_A339
    );
    // A single byte flip must change the CRC (error detection is the whole point).
    assert_ne!(standard_crc32(b"123456789"), standard_crc32(b"123456780"));
}

// ── base62 encode: exact known encodings + structural edges ───────────────────

#[test]
fn base62_encode_known_and_edge_values() {
    assert_eq!(base62_encode_u32(0, 6), "000000"); // zero → all-pad
    assert_eq!(base62_encode_u32(1, 6), "000001");
    assert_eq!(base62_encode_u32(61, 6), "00000z"); // last single digit
    assert_eq!(base62_encode_u32(62, 6), "000010"); // carry into 2nd digit
                                                    // u32::MAX needs all six digits (62^5 < 2^32 <= 62^6).
    assert_eq!(base62_encode_u32(u32::MAX, 6).len(), 6);
    assert_eq!(
        base62_decode(&base62_encode_u32(u32::MAX, 6)),
        u32::MAX as u64
    );
}

// ── crc32_base62_suffix is the exact composition ─────────────────────────────

#[test]
fn suffix_is_encode_of_crc() {
    let data = b"abcdef0123456789abcdef0123456789"; // 30-char github body shape
    assert_eq!(
        crc32_base62_suffix(data, 6),
        base62_encode_u32(standard_crc32(data), 6)
    );
    assert_eq!(crc32_base62_suffix(data, 6).len(), 6);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8_000))]

    /// For width 6, EVERY `u32` encodes to exactly six base62 chars whose reverse
    /// decode is the original value — the encoder is a total, injective inverse
    /// over the whole `u32` domain (62^6 > 2^32).
    #[test]
    fn base62_width6_roundtrips_every_u32(v in any::<u32>()) {
        let enc = base62_encode_u32(v, 6);
        prop_assert_eq!(enc.len(), 6);
        prop_assert!(enc.bytes().all(|b| BASE62_DIGITS.contains(&b)));
        prop_assert_eq!(base62_decode(&enc), v as u64);
    }

    /// Padding is left-side only and never truncates: the encoding of a value that
    /// needs `k` digits is `(width-k)` leading '0's followed by the significant
    /// digits, so widening only adds leading zeros and never changes the decode.
    #[test]
    fn wider_padding_preserves_value(v in any::<u32>(), extra in 0usize..6) {
        let width = 6 + extra;
        let enc = base62_encode_u32(v, width);
        prop_assert_eq!(enc.len(), width);
        prop_assert_eq!(base62_decode(&enc), v as u64);
    }

    /// CRC-32 is deterministic and a genuine hash: identical input → identical
    /// output, and appending a byte (almost) always perturbs it. Determinism is
    /// the invariant a fabricated-token check relies on.
    #[test]
    fn crc32_is_deterministic(data in prop::collection::vec(any::<u8>(), 0..128)) {
        prop_assert_eq!(standard_crc32(&data), standard_crc32(&data));
        // The suffix over the same bytes is likewise stable.
        prop_assert_eq!(crc32_base62_suffix(&data, 6), crc32_base62_suffix(&data, 6));
    }
}
