//! Regression: CPU decoder base/reverse PARITY for the decode-through primitives
//! in `crates/scanner/src/decode/{hex,base64,reverse,caesar}.rs`.
//!
//! This file is host-independent and GPU-free: it exercises only the pure CPU
//! decode primitives (`hex_decode`, `base64_decode`, `z85_decode`, the
//! `find_*` extractors) plus the decode-gated reverse/caesar/registry seams.
//! The primitive tests use ONLY the unconditional `decode` public API so the
//! file still compiles and runs under `--no-default-features` (no gpu, no
//! decode feature); the reverse/caesar/pipeline-order tests live behind
//! `#[cfg(feature = "decode")]`.
//!
//! Parity contract proven here (every assertion pins a CONCRETE value, exact
//! decoded bytes, exact `Err(())`, exact candidate string, exact reversed /
//! rotated string):
//!   * `decode(encode(x)) == x` for hand-encoded fixtures across hex, the four
//!     base64 alphabet variants, and z85.
//!   * The SAME plaintext encoded two ways (hex vs base64; standard vs url-safe
//!     alphabet) decodes to byte-identical output (alphabet-resolve parity).
//!   * An ambiguous run that is simultaneously valid hex AND valid base64
//!     resolves to two DISTINCT deterministic byte strings (the two decoders are
//!     independent primitives, not a single overloaded path).
//!   * Reverse and ROT-N are their own inverses (`f(f(x)) == x`), the
//!     round-trip parity the evasion decoders rely on.
//!   * Invalid inputs fail closed to the exact `Err(())` / rejection.

use keyhog_scanner::decode::{
    base64_decode, find_base64_strings, find_hex_strings, hex_decode, is_base64_candidate_byte,
    z85_decode,
};

// ── decode(encode(x)) == x : single-alphabet round-trips ─────────────────────

#[test]
fn hex_roundtrip_secret_token_exact_bytes() {
    // "secret-token-42" hex-encoded (30 hex chars, clears the 16-char floor).
    assert_eq!(
        hex_decode("7365637265742d746f6b656e2d3432").unwrap(),
        b"secret-token-42".to_vec()
    );
}

#[test]
fn base64_roundtrip_secret_token_standard_exact_bytes() {
    // "secret-token-42" standard base64 (len 20, len%4==0, no padding) routes
    // through the Standard variant and must reproduce the identical bytes.
    assert_eq!(
        base64_decode("c2VjcmV0LXRva2VuLTQy").unwrap(),
        b"secret-token-42".to_vec()
    );
}

// ── cross-decoder parity: same plaintext, different encoding, equal bytes ─────

#[test]
fn hex_base64_padded_and_nopad_decode_to_identical_bytes() {
    // The AWS example access-key-id encoded three ways. Hex, padded standard
    // base64, and unpadded standard base64 must all resolve to the exact same
    // 20 plaintext bytes (the decode-through pipeline's parity guarantee).
    let expected = b"AKIAIOSFODNN7EXAMPLE".to_vec();
    let via_hex = hex_decode("414b4941494f53464f444e4e374558414d504c45").unwrap();
    let via_b64_padded = base64_decode("QUtJQUlPU0ZPRE5ON0VYQU1QTEU=").unwrap();
    let via_b64_nopad = base64_decode("QUtJQUlPU0ZPRE5ON0VYQU1QTEU").unwrap();
    assert_eq!(via_hex, expected);
    assert_eq!(via_b64_padded, expected);
    assert_eq!(via_b64_nopad, expected);
    // Padded and unpadded standard base64 agree byte-for-byte.
    assert_eq!(via_b64_padded, via_b64_nopad);
}

#[test]
fn base64_standard_and_urlsafe_alphabets_decode_to_identical_bytes() {
    // "xy>>?~zz--__==test" encoded once in the standard alphabet (uses '+') and
    // once in the url-safe alphabet (uses '-'). Different alphabet, byte-for-byte
    // identical decode (the classifier must resolve each to the right variant).
    let expected = b"xy>>?~zz--__==test".to_vec();
    let via_standard = base64_decode("eHk+Pj9+enotLV9fPT10ZXN0").unwrap();
    let via_urlsafe = base64_decode("eHk-Pj9-enotLV9fPT10ZXN0").unwrap();
    assert_eq!(via_standard, expected);
    assert_eq!(via_urlsafe, expected);
    assert_eq!(via_standard, via_urlsafe);
}

#[test]
fn base64_urlsafe_nopad_yields_exact_nonutf8_bytes() {
    // "-_-_-_-_" is the url-safe-no-pad encoding of 6 high bytes. The url-safe
    // alphabet maps '-'->62 and '_'->63, so decode must yield exactly these
    // bytes (deliberately non-UTF-8, proving the primitive returns raw Vec<u8>).
    assert_eq!(
        base64_decode("-_-_-_-_").unwrap(),
        vec![251u8, 255, 191, 251, 255, 191]
    );
}

// ── resolve precedence: an ambiguous run decodes distinctly per decoder ───────

#[test]
fn ambiguous_run_hex_vs_base64_resolve_to_distinct_bytes() {
    // "deadbeefdeadbeef" is simultaneously valid hex (all hex digits) AND valid
    // standard base64 (all alnum, len 16, %4==0). The two decoders are separate
    // primitives: hex resolves it to 8 bytes, base64 to 12, both deterministic,
    // never conflated into one overloaded path.
    let blob = "deadbeefdeadbeef";
    assert_eq!(
        hex_decode(blob).unwrap(),
        vec![0xdeu8, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef]
    );
    assert_eq!(
        base64_decode(blob).unwrap(),
        vec![117u8, 230, 157, 109, 231, 159, 117, 230, 157, 109, 231, 159]
    );
    // Distinct lengths confirm they did not resolve through the same path.
    assert_ne!(
        hex_decode(blob).unwrap().len(),
        base64_decode(blob).unwrap().len()
    );
}

#[test]
fn hex_underscore_grouped_and_plain_decode_to_identical_bytes() {
    // Firmware/config hex commonly groups bytes with '_'. Grouped and plain
    // spellings of the same value must strip to byte-identical output.
    let plain = hex_decode("7365637265742d746f6b656e2d3432").unwrap();
    let grouped = hex_decode("73_65_63_72_65_74_2d_74_6f_6b_65_6e_2d_34_32").unwrap();
    assert_eq!(grouped, b"secret-token-42".to_vec());
    assert_eq!(grouped, plain);
}

// ── fail-closed rejections: exact Err(()) ────────────────────────────────────

#[test]
fn hex_odd_length_and_non_hex_reject_to_err() {
    // Odd digit count (29 chars) is not a whole number of bytes; a non-hex byte
    // is not the hex alphabet. Both fail closed.
    assert_eq!(hex_decode("7365637265742d746f6b656e2d343"), Err(()));
    assert_eq!(hex_decode("zzzz"), Err(()));
}

#[test]
fn base64_padded_wrong_remainder_rejected() {
    // A padded blob whose length is not a multiple of 4 (len 9, '=' at end) is
    // not valid base64: classify returns None, decode fails closed.
    assert_eq!(base64_decode("aGVsbG8x="), Err(()));
}

#[test]
fn base64_nopad_remainder_one_rejected() {
    // len 17, len%4==1, unpadded: a single leftover base64 char can never be a
    // whole byte group, so the classifier rejects it.
    assert_eq!(base64_decode("QUtJQUlPU0ZPRE5ON"), Err(()));
}

#[test]
fn base64_mixed_standard_and_urlsafe_alphabet_rejected() {
    // Contains BOTH '+' (standard) and '-' (url-safe): an ambiguous alphabet the
    // classifier refuses rather than silently guessing a variant.
    assert_eq!(base64_decode("AAAA+BBBB-CCCC1234"), Err(()));
}

// ── z85 frame parity + adversarial symbol reject ─────────────────────────────

#[test]
fn z85_reference_frame_decodes_and_invalid_symbol_rejects() {
    // Canonical RFC 32/Z85 vector "HelloWorld" -> the 8-byte frame.
    assert_eq!(
        z85_decode("HelloWorld").unwrap(),
        vec![134u8, 79, 210, 111, 181, 89, 247, 91]
    );
    // A length-valid frame (5 chars) containing a byte outside the z85 alphabet
    // ('`' = 0x60) fails closed rather than decoding garbage.
    assert_eq!(z85_decode("Hell`"), Err(()));
}

// ── extractor parity: an ambiguous run surfaces from BOTH find_* extractors ───

#[test]
fn find_hex_and_find_base64_surface_same_ambiguous_run() {
    // "68656c6c6f68656c" is a 16-char run that is a valid hex string AND a valid
    // standard base64 candidate. Both extractors must surface it as exactly one
    // candidate with the exact value (parity of the pre-decode extraction gate).
    let blob = "68656c6c6f68656c";
    let hex_cands: Vec<String> = find_hex_strings(blob, 16)
        .into_iter()
        .map(|e| e.value)
        .collect();
    let b64_cands: Vec<String> = find_base64_strings(blob, 16)
        .into_iter()
        .map(|e| e.value)
        .collect();
    assert_eq!(hex_cands, vec![blob.to_string()]);
    assert_eq!(b64_cands, vec![blob.to_string()]);
}

#[test]
fn is_base64_candidate_byte_alphabet_exact_membership() {
    // The single canonical base64/url-safe alphabet predicate: alnum plus the
    // six symbol bytes are IN; whitespace, '*', '.', '!', '%' are OUT.
    for b in [b'A', b'z', b'0', b'9', b'+', b'/', b'=', b'-', b'_'] {
        assert!(
            is_base64_candidate_byte(b),
            "expected {} in alphabet",
            b as char
        );
    }
    for b in [b' ', b'\t', b'\n', b'*', b'.', b'!', b'%', b'#'] {
        assert!(
            !is_base64_candidate_byte(b),
            "expected {} out of alphabet",
            b as char
        );
    }
}

// ── reverse / caesar involution + pipeline order (decode feature only) ────────

#[cfg(feature = "decode")]
mod decode_feature {
    use keyhog_scanner::testing::{
        caesar_shift_for_test, default_decoder_names_for_test, looks_reversible_for_test,
        reverse_str_for_test,
    };

    #[test]
    fn reverse_str_is_its_own_inverse() {
        // reverse(reverse(x)) == x, the involution the reverse decoder relies on
        // to refuse recursing on its own `/reverse` output. Exact reversed value.
        let original = "secret-token-42";
        let reversed = reverse_str_for_test(original);
        assert_eq!(reversed, "24-nekot-terces");
        assert_eq!(reverse_str_for_test(&reversed), original);
    }

    #[test]
    fn reverse_admission_gate_accepts_documented_reversed_aws_key() {
        // The adversarial-corpus reversed AWS access-key candidate carries a 12+
        // alnum run and a reversed known prefix, so the gate admits it (true);
        // a long alnum run with no reversed provider prefix is rejected (false).
        assert!(looks_reversible_for_test("RNK1ESEMURKWESFEDBA-46AIKA"));
        assert!(!looks_reversible_for_test("ZYXWVUTSRQPONMLKJIHGFEDCBA"));
    }

    #[test]
    fn caesar_rot13_is_its_own_inverse_and_leaves_digits_untouched() {
        // ROT13 applied twice is the identity; digits and punctuation pass through
        // unchanged. Exact rotated strings pin the alphabet math.
        assert_eq!(caesar_shift_for_test("AKIA1234", 13), "NXVN1234");
        assert_eq!(
            caesar_shift_for_test(&caesar_shift_for_test("AKIA1234", 13), 13),
            "AKIA1234"
        );
        // A forward shift of 3 and its complement 23 round-trip exactly.
        assert_eq!(caesar_shift_for_test("Hello", 3), "Khoor");
        assert_eq!(caesar_shift_for_test("Khoor", 23), "Hello");
    }

    #[test]
    fn default_decoder_pipeline_order_runs_reverse_and_caesar_last() {
        // The pipeline composition is load-bearing: the direct alphabet decoders
        // (base64, hex) run FIRST and the evasion decoders (reverse, caesar) run
        // LAST, after every structural decoder. Pin the boundary positions and
        // the total count so a reorder or addition can't silently shift it.
        let names = default_decoder_names_for_test();
        assert_eq!(names.len(), 13);
        assert_eq!(&names[..2], &["base64", "hex"]);
        assert_eq!(&names[names.len() - 2..], &["reverse", "caesar"]);
    }
}
