//! Regression coverage for the Z85 decoder (`decode::z85_decode`) and the
//! reverse decoder's public test seams (`testing::reverse_str_for_test`,
//! `testing::looks_reversible_for_test`).
//!
//! Every assertion pins a CONCRETE expected value (exact bytes / bool /
//! `Err(())`), never a shape check. These paths are pure scalar CPU code with
//! no accelerator dependency, so the contracts are fully host-independent.
//!
//! Z85 alphabet reference: ZeroMQ RFC 32
//! `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#`

use keyhog_scanner::decode::z85_decode;
use keyhog_scanner::testing::{looks_reversible_for_test, reverse_str_for_test};

// ---------------------------------------------------------------------------
// Z85 decoder, decode(encode(x)) == x for known vectors
// ---------------------------------------------------------------------------

#[test]
fn z85_decodes_zeromq_hello_world_reference_vector() {
    // The canonical ZeroMQ Z85 test vector: "HelloWorld" is the encoding of
    // these exact 8 bytes.
    assert_eq!(
        z85_decode("HelloWorld"),
        Ok(vec![0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B]),
    );
}

#[test]
fn z85_decodes_all_zero_frame_to_four_zero_bytes() {
    // "00000" is index-0 five times => u32 value 0 => four 0x00 bytes.
    assert_eq!(z85_decode("00000"), Ok(vec![0u8, 0, 0, 0]));
}

#[test]
fn z85_decodes_max_u32_frame_to_four_ff_bytes() {
    // "%nSc0" is the encoding of u32::MAX (0xFFFF_FFFF), the largest value a
    // single 5-char Z85 frame may legally represent.
    assert_eq!(z85_decode("%nSc0"), Ok(vec![0xFF, 0xFF, 0xFF, 0xFF]));
}

#[test]
fn z85_roundtrip_known_encodings_recover_original_bytes() {
    // decode(encode(x)) == x, expressed as decode(known_encoding) == x for
    // pre-computed encodings. Covers arbitrary bytes, a low value, and ASCII.
    assert_eq!(z85_decode("?MsJX"), Ok(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    assert_eq!(z85_decode("0rJug"), Ok(vec![0x01, 0x02, 0x03, 0x0A]));
    // "yH}^8z!yjp" encodes the ASCII bytes of "keyhog!!".
    assert_eq!(z85_decode("yH}^8z!yjp"), Ok(b"keyhog!!".to_vec()));
}

#[test]
fn z85_decodes_two_frames_contiguously() {
    // 10 chars => two 5-char frames => 8 bytes, in frame order.
    // "00000" (0,0,0,0) followed by "%nSc0" (ff,ff,ff,ff).
    assert_eq!(
        z85_decode("00000%nSc0"),
        Ok(vec![0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]),
    );
}

#[test]
fn z85_empty_input_decodes_to_empty_vec() {
    // 0 % 5 == 0, no frames => Ok of an empty byte vector (a concrete value,
    // not merely "is_ok").
    assert_eq!(z85_decode(""), Ok(Vec::<u8>::new()));
}

// ---------------------------------------------------------------------------
// Z85 decoder, negative / boundary / adversarial: must fail closed with Err
// ---------------------------------------------------------------------------

#[test]
fn z85_length_not_multiple_of_five_is_err() {
    // "Hell" is 4 chars (not a whole frame. Fails closed).
    assert_eq!(z85_decode("Hell"), Err(()));
    // 6 chars is one full frame plus a dangling char (also rejected).
    assert_eq!(z85_decode("HelloW"), Err(()));
}

#[test]
fn z85_bad_symbol_is_err() {
    // Backtick (0x60) sits between '_' and 'a' and is NOT in the Z85 alphabet.
    // Present in an otherwise-valid 5-char frame => whole decode fails.
    assert_eq!(z85_decode("Hell`"), Err(()));
    // A space is likewise not an alphabet symbol.
    assert_eq!(z85_decode("Hell "), Err(()));
}

#[test]
fn z85_frame_value_overflowing_u32_is_err() {
    // "#####" is index-84 five times = 85^5 - 1 = 4_437_053_124, which exceeds
    // u32::MAX (4_294_967_295). The decoder must reject the overflow, not wrap.
    assert!(85u64.pow(5) - 1 > u32::MAX as u64);
    assert_eq!(z85_decode("#####"), Err(()));
}

// ---------------------------------------------------------------------------
// Reverse decoder, reverse_str involution and secret recovery
// ---------------------------------------------------------------------------

#[test]
fn reverse_str_is_an_involution() {
    // f(f(x)) == x for ASCII and for multibyte Unicode (reversed by scalar).
    let ascii = "AKIAIOSFODNN7EXAMPLE";
    assert_eq!(reverse_str_for_test(&reverse_str_for_test(ascii)), ascii);

    let unicode = "café_reverse_TOKEN123";
    assert_eq!(
        reverse_str_for_test(&reverse_str_for_test(unicode)),
        unicode
    );

    // And the single application is exactly the char-reversed string.
    assert_eq!(reverse_str_for_test("abc123"), "321cba");
    // Unicode: the é is reversed as one scalar, not split into bytes.
    assert_eq!(reverse_str_for_test("café"), "éfac");
}

#[test]
fn reverse_str_recovers_a_reversed_aws_key() {
    // "ELPMAXE7NNDOFSOIAIKA" is the char-reversal of the canonical AWS example
    // access-key-id "AKIAIOSFODNN7EXAMPLE"; reversing again recovers it exactly.
    assert_eq!(
        reverse_str_for_test("ELPMAXE7NNDOFSOIAIKA"),
        "AKIAIOSFODNN7EXAMPLE",
    );
}

// ---------------------------------------------------------------------------
// Reverse decoder, looks_reversible admission gate (exact bool)
// ---------------------------------------------------------------------------

#[test]
fn looks_reversible_true_for_reversed_aws_key() {
    // Reversed AWS key: 20-char alnum run (>= 12) AND its reverse contains the
    // known prefix "AKIA" (i.e. the candidate contains "AIKA"). Both gates pass.
    assert_eq!(looks_reversible_for_test("ELPMAXE7NNDOFSOIAIKA"), true);
}

#[test]
fn looks_reversible_true_for_reversed_ghp_token() {
    // Candidate "21jihgfedcba_phg" reverses to "ghp_abcdefghij12": 12-char alnum
    // run before the underscore, and it contains "_phg" (reverse of "ghp_").
    assert_eq!(looks_reversible_for_test("21jihgfedcba_phg"), true);
}

#[test]
fn looks_reversible_false_without_known_prefix() {
    // 26-char alnum run (gate 1 passes) but the reverse ("ABC..XYZ") contains no
    // known credential prefix => rejected. This is the exact FP the prefix gate
    // exists to stop.
    assert_eq!(
        looks_reversible_for_test("ZYXWVUTSRQPONMLKJIHGFEDCBA"),
        false
    );
}

#[test]
fn looks_reversible_run_length_boundary_at_twelve() {
    // Exactly 12 contiguous alnum chars, and contains "AIKA" (reverse of AKIA):
    // gate 1 is satisfied at the boundary => true.
    assert_eq!(looks_reversible_for_test("AIKA12345678"), true);
    // One shorter (11-char run): gate 1 fails even though "AIKA" is present.
    assert_eq!(looks_reversible_for_test("AIKA1234567"), false);
}

#[test]
fn looks_reversible_false_short_run_even_with_reversed_prefix() {
    // Contains "-ks" (reverse of the known prefix "sk-"), so the prefix gate
    // alone would pass, but the longest alnum run is only 5 (< 12), so gate 1
    // rejects it first. Proves the run gate is independent and enforced.
    assert_eq!(looks_reversible_for_test("x-ksxyz"), false);
}
