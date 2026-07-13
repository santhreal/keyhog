//! Adversarial decompression-bomb contracts for the decode-through inflate path
//! (`crates/scanner/src/decode/inflate.rs`).
//!
//! `try_inflate_to_text` inflates attacker-controlled gzip/zlib blobs so a
//! `secret -> gzip -> base64` exfil shape is rescanned. Compression is the
//! canonical amplification DoS: a few KiB of input can encode gigabytes of
//! output. The decoder caps inflation at `MAX_INFLATE_BYTES` (16 MiB) via a
//! `Read::take` wrapper. These tests build REAL bombs (a tiny gzip/zlib blob
//! that would expand far past the cap) and assert:
//!   1. no panic, no OOM, no hang (a regressed cap would blow the box here),
//!   2. any returned text is <= the cap,
//!   3. a legitimate small round-trip still inflates correctly (the cap does not
//!      break the happy path (recall preserved)).
//!
//! If the `Read::take` guard is ever removed, `huge_bomb_is_capped` OOMs/hangs
//! instead of passing, the failure is LOUD, exactly as a DoS regression should
//! be.

#![cfg(feature = "decode")]

use keyhog_scanner::testing::{
    gzip_compress_for_test, inflate_output_cap_for_test, try_inflate_to_text_for_test,
    zlib_compress_for_test,
};
use proptest::prelude::*;

/// 256 MiB of a single repeated byte, compresses to a few KiB of gzip, but
/// would inflate to 256 MiB if uncapped (16x the 16 MiB ceiling).
const BOMB_PLAINTEXT: usize = 256 * 1024 * 1024;

// ── the decompression bomb (the DoS class) ───────────────────────────────────

#[test]
fn huge_gzip_bomb_is_capped_not_oom() {
    // A quarter-GiB of 'A' → a tiny gzip blob.
    let bomb = gzip_compress_for_test(&vec![b'A'; BOMB_PLAINTEXT]);
    // Sanity: the compressed blob is orders of magnitude smaller than the cap,
    // so this is a genuine amplification bomb, not a large literal.
    assert!(
        bomb.len() < 1024 * 1024,
        "bomb blob should be tiny (<1 MiB), got {} bytes",
        bomb.len()
    );
    let cap = inflate_output_cap_for_test();
    // Must NOT OOM/hang: the take() guard truncates at the cap. A truncated
    // all-'A' stream is still valid UTF-8, so this returns Some(text) bounded by
    // the cap (the exact byte where flate2 stops relative to the cap can vary,
    // so allow a small slack above the ceiling but never unbounded growth).
    let out = try_inflate_to_text_for_test(&bomb);
    if let Some(text) = out {
        assert!(
            text.len() <= cap + 64 * 1024,
            "inflate output {} exceeded cap {}, bomb bound regressed",
            text.len(),
            cap
        );
    }
}

#[test]
fn huge_zlib_bomb_is_capped_not_oom() {
    let bomb = zlib_compress_for_test(&vec![b'Z'; BOMB_PLAINTEXT]);
    assert!(bomb.len() < 1024 * 1024, "zlib bomb blob should be tiny");
    let cap = inflate_output_cap_for_test();
    if let Some(text) = try_inflate_to_text_for_test(&bomb) {
        assert!(
            text.len() <= cap + 64 * 1024,
            "zlib inflate output {} exceeded cap {}",
            text.len(),
            cap
        );
    }
}

// ── happy path: the cap does not break legitimate small inflate (recall) ─────

#[test]
fn small_gzip_round_trips_through_inflate() {
    let secret = "AKIAIOSFODNN7EXAMPLE token=ghp_smallpayloadroundtrip";
    let blob = gzip_compress_for_test(secret.as_bytes());
    let out = try_inflate_to_text_for_test(&blob).expect("small gzip inflates to text");
    assert_eq!(out, secret, "small payload must round-trip exactly");
}

#[test]
fn small_zlib_round_trips_through_inflate() {
    let secret = "password=zlibpayload1234567890";
    let blob = zlib_compress_for_test(secret.as_bytes());
    let out = try_inflate_to_text_for_test(&blob).expect("small zlib inflates to text");
    assert_eq!(out, secret);
}

// ── non-container and malformed inputs return None, never panic ──────────────

#[test]
fn non_container_and_malformed_inputs_return_none() {
    // Plain text (no magic) → None.
    assert!(try_inflate_to_text_for_test(b"just plain text, not compressed").is_none());
    // Empty → None.
    assert!(try_inflate_to_text_for_test(b"").is_none());
    // gzip magic but garbage body → decode error → None (not a panic).
    assert!(try_inflate_to_text_for_test(&[0x1f, 0x8b, 0xff, 0xff, 0xff, 0xff]).is_none());
    // zlib magic but garbage body → None.
    assert!(try_inflate_to_text_for_test(&[0x78, 0x9c, 0x00, 0x00, 0x00]).is_none());
    // Truncated gzip (magic only) → None.
    assert!(try_inflate_to_text_for_test(&[0x1f, 0x8b]).is_none());
}

#[test]
fn empty_inflate_output_returns_none_not_empty_some() {
    // A gzip/zlib of the empty payload inflates to "", but an empty result has
    // nothing to rescan, so the decoder collapses it to `None` (consistent with
    // the other non-productive paths), never `Some("")`.
    assert!(
        try_inflate_to_text_for_test(&gzip_compress_for_test(b"")).is_none(),
        "empty gzip payload must return None, not Some(\"\")"
    );
    assert!(
        try_inflate_to_text_for_test(&zlib_compress_for_test(b"")).is_none(),
        "empty zlib payload must return None, not Some(\"\")"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_500))]

    /// Any gzip of arbitrary small bytes round-trips: inflating the compressed
    /// form yields exactly the original (when the original is valid UTF-8).
    #[test]
    fn gzip_round_trips_arbitrary_utf8(s in "\\PC{1,512}") {
        // Non-empty payload (empty → None by the empty-collapse rule, tested
        // separately); any non-empty UTF-8 round-trips exactly.
        let blob = gzip_compress_for_test(s.as_bytes());
        let out = try_inflate_to_text_for_test(&blob);
        prop_assert_eq!(out.as_deref(), Some(s.as_str()));
    }

    /// Arbitrary bytes prefixed with a gzip magic never panic and, if they
    /// inflate at all, stay bounded by the cap.
    #[test]
    fn gzip_magic_prefixed_garbage_never_panics(body in prop::collection::vec(any::<u8>(), 0..4096)) {
        let mut blob = vec![0x1f, 0x8b];
        blob.extend_from_slice(&body);
        let cap = inflate_output_cap_for_test();
        if let Some(text) = try_inflate_to_text_for_test(&blob) {
            prop_assert!(text.len() <= cap + 64 * 1024);
        }
    }

    /// Arbitrary NON-magic bytes always return None (the magic gate never
    /// misfires on random input, which would waste inflate work).
    #[test]
    fn non_magic_bytes_return_none(body in prop::collection::vec(any::<u8>(), 0..256)) {
        // Force the first two bytes off both magics.
        let mut blob = vec![0x00, 0x00];
        blob.extend_from_slice(&body);
        prop_assert!(try_inflate_to_text_for_test(&blob).is_none());
    }
}
