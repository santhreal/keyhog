//! Property + fuzz coverage for the public hot-path decoders (#177).
//!
//! The known-answer suite (`decode_codec_vectors`) pins specific vectors; this
//! proves the invariants that must hold for ALL inputs:
//!   1. ROUNDTRIP — for every byte string, `decode(encode(bytes)) == bytes`.
//!      The reference encoders here are self-checked against a fixed vector
//!      first, so a roundtrip failure isolates to keyhog's DECODER (a real bug
//!      to report, never a test to weaken — Law 6/9), not to a wrong encoder.
//!   2. PANIC-SAFETY — no arbitrary input (hostile, truncated, mixed-alphabet)
//!      may panic a decoder. These run on the scan hot path over attacker-
//!      controlled bytes, so a slice-boundary/overflow panic is a DoS.

use keyhog_scanner::decode::{base64_decode, hex_decode, z85_decode};
use proptest::prelude::*;

// ── self-checked reference encoders ──────────────────────────────────────────

fn hex_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Standard base64 (RFC 4648) WITH `=` padding.
fn b64_encode(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(A[(b0 >> 2) as usize]);
        out.push(A[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]);
        out.push(if chunk.len() > 1 {
            A[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize]
        } else {
            b'='
        });
        out.push(if chunk.len() > 2 {
            A[(b2 & 0x3f) as usize]
        } else {
            b'='
        });
    }
    String::from_utf8(out).expect("base64 alphabet is ASCII")
}

/// ZeroMQ RFC 32 Z85. `data.len()` must be a multiple of 4.
fn z85_encode(data: &[u8]) -> String {
    const A: &[u8; 85] =
        b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
    assert_eq!(data.len() % 4, 0, "z85 input must be a multiple of 4 bytes");
    let mut out = Vec::with_capacity(data.len() / 4 * 5);
    for chunk in data.chunks(4) {
        let mut value = (u32::from(chunk[0]) << 24)
            | (u32::from(chunk[1]) << 16)
            | (u32::from(chunk[2]) << 8)
            | u32::from(chunk[3]);
        let mut buf = [0u8; 5];
        for slot in buf.iter_mut().rev() {
            *slot = A[(value % 85) as usize];
            value /= 85;
        }
        out.extend_from_slice(&buf);
    }
    String::from_utf8(out).expect("z85 alphabet is ASCII")
}

#[test]
fn reference_encoders_match_known_vectors() {
    // If these hold, the reference encoders are correct, so any roundtrip
    // failure below is keyhog's decoder — not a wrong encoder here.
    assert_eq!(hex_encode(b"Hello"), "48656c6c6f");
    assert_eq!(b64_encode(b"hello"), "aGVsbG8=");
    assert_eq!(b64_encode(b"Hello, World!"), "SGVsbG8sIFdvcmxkIQ==");
    assert_eq!(
        z85_encode(&[0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B]),
        "HelloWorld"
    );
}

// ── roundtrip invariants (10k cases each) ────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn hex_decode_inverts_hex_encode(data in proptest::collection::vec(any::<u8>(), 1..256)) {
        let encoded = hex_encode(&data);
        let decoded = hex_decode(&encoded);
        prop_assert!(decoded.is_ok(), "hex_decode rejected valid hex {encoded:?}: {decoded:?}");
        prop_assert_eq!(decoded.unwrap(), data);
    }

    #[test]
    fn base64_decode_inverts_base64_encode(data in proptest::collection::vec(any::<u8>(), 1..256)) {
        let encoded = b64_encode(&data);
        let decoded = base64_decode(&encoded);
        prop_assert!(decoded.is_ok(), "base64_decode rejected valid base64 {encoded:?}: {decoded:?}");
        prop_assert_eq!(decoded.unwrap(), data);
    }

    #[test]
    fn z85_decode_inverts_z85_encode(groups in proptest::collection::vec(any::<[u8; 4]>(), 1..48)) {
        let data: Vec<u8> = groups.concat();
        let encoded = z85_encode(&data);
        let decoded = z85_decode(&encoded);
        prop_assert!(decoded.is_ok(), "z85_decode rejected valid z85 {encoded:?}: {decoded:?}");
        prop_assert_eq!(decoded.unwrap(), data);
    }
}

// ── panic-safety on hostile input (no decoder may crash) ─────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Bias the generator toward the decode alphabets + separators + a little
    /// garbage so cases reach DEEP into the decode logic (past the early
    /// reject), where a slice/index bug would live — not just trivial rejects.
    #[test]
    fn decoders_never_panic(s in "[A-Za-z0-9+/=_\\-. \t\r\n!:]{0,300}") {
        // Success or Err are both fine; a PANIC fails the case with the minimal
        // crashing input. Whatever a decoder returns Ok for must decode without
        // crashing the re-scan, so exercise the returned bytes' length too.
        if let Ok(v) = base64_decode(&s) {
            prop_assert!(v.len() <= s.len());
        }
        if let Ok(v) = hex_decode(&s) {
            prop_assert!(v.len() <= s.len());
        }
        if let Ok(v) = z85_decode(&s) {
            prop_assert!(v.len() <= s.len());
        }
    }
}
