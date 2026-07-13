//! Known-answer codec tests for the public decode primitives (#177).
//!
//! These decoders sit on the scan hot path (an encoded blob is decoded, then
//! re-scanned for secrets), so a silent-accept or truncation bug is a recall
//! hole. Each case asserts the EXACT decoded bytes against a standard vector
//! (Law 6), plus the reject paths that must fail closed with `Err(())`.

use keyhog_scanner::decode::{base64_decode, hex_decode, z85_decode};

// ── base64 ────────────────────────────────────────────────────────────────

#[test]
fn base64_decodes_standard_vectors_to_exact_bytes() {
    assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
    assert_eq!(
        base64_decode("SGVsbG8sIFdvcmxkIQ==").unwrap(),
        b"Hello, World!"
    );
    // The all-bytes RFC 4648 vector "\x00\x10\x83..." would need binary; use a
    // round-trippable ASCII one that also exercises a non-`=`-padded length.
    assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
}

#[test]
fn base64_accepts_url_safe_alphabet() {
    // URL-safe uses `-`/`_` where standard uses `+`/`/`. Bytes 0xFB 0xFF 0xBF
    // encode as "-_-_" in base64url (standard would be "+/+/").
    assert_eq!(base64_decode("-_-_").unwrap(), vec![0xFB, 0xFF, 0xBF]);
}

#[test]
fn base64_rejects_non_alphabet_input() {
    assert!(base64_decode("!!!!").is_err());
    assert!(base64_decode("aGVsbG8*").is_err());
}

// ── hex ─────────────────────────────────────────────────────────────────────

#[test]
fn hex_decodes_lower_and_upper_case_to_exact_bytes() {
    assert_eq!(hex_decode("48656c6c6f").unwrap(), b"Hello");
    assert_eq!(hex_decode("48656C6C6F").unwrap(), b"Hello"); // case-insensitive
    assert_eq!(
        hex_decode("deadbeef").unwrap(),
        vec![0xde, 0xad, 0xbe, 0xef]
    );
}

#[test]
fn hex_ignores_underscore_separators() {
    // The `_`-bearing branch strips separators before decoding.
    assert_eq!(
        hex_decode("de_ad_be_ef").unwrap(),
        vec![0xde, 0xad, 0xbe, 0xef]
    );
}

#[test]
fn hex_rejects_odd_length_and_non_hex() {
    assert!(hex_decode("abc").is_err()); // odd nibble count
    assert!(hex_decode("xyz0").is_err()); // non-hex digits
                                          // Guards against the historical multibyte silent-accept: a non-ASCII char
                                          // must NOT decode to empty-success.
    assert!(hex_decode("48é6").is_err());
}

// ── z85 ─────────────────────────────────────────────────────────────────────

#[test]
fn z85_decodes_the_rfc32_reference_frame() {
    // ZeroMQ RFC 32 reference: the 8-byte frame below encodes to "HelloWorld".
    assert_eq!(
        z85_decode("HelloWorld").unwrap(),
        vec![0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B]
    );
}

#[test]
fn z85_rejects_length_not_a_multiple_of_five() {
    assert!(z85_decode("Hell").is_err()); // 4 chars
    assert!(z85_decode("HelloWorl").is_err()); // 9 chars
}

// ── DoS bound (fail closed for a security control) ───────────────────────────

#[test]
fn decoders_fail_closed_on_oversized_input() {
    // Anti-DoS: base64/z85 cap input at 16 MiB, hex at 32 MiB. Input past the
    // cap must return Err via an O(1) length check, never hang or allocate the
    // (potentially huge) decoded output. Content is all-`A` (valid in every
    // alphabet) so the reject is driven purely by size, not by an invalid byte.
    let over_hex = "A".repeat(33 * 1024 * 1024); // > 32 MiB hex cap
    assert!(hex_decode(&over_hex).is_err(), "hex must reject > 32 MiB");
    // 20 MiB: a multiple of 5 (so z85 rejects on SIZE, not the length-parity
    // check) and above the 16 MiB base64/z85 cap.
    let over_16 = &over_hex[..20 * 1024 * 1024];
    assert!(
        base64_decode(over_16).is_err(),
        "base64 must reject > 16 MiB"
    );
    assert!(z85_decode(over_16).is_err(), "z85 must reject > 16 MiB");
}
