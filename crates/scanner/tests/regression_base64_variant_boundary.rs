//! Regression: base64 standard vs url-safe alphabet parity and variant
//! boundaries for the decode-through front door
//! (`crates/scanner/src/decode/base64.rs`).
//!
//! Contract under test (every assertion pins a CONCRETE value — exact decoded
//! bytes, exact `Err(())`, exact per-byte booleans — never shape):
//!   * The standard alphabet (`+` = index 62, `/` = index 63) and the url-safe
//!     alphabet (`-` = 62, `_` = 63) are DISTINCT byte strings that decode to
//!     BYTE-IDENTICAL output. A drift that mis-maps `-_` <-> `+/` silently
//!     corrupts decoded credentials.
//!   * Padded and unpadded forms of the same payload decode identically
//!     (`STANDARD`/`STANDARD_NO_PAD`, `URL_SAFE`/`URL_SAFE_NO_PAD`).
//!   * `len % 4 == 1` is never a whole base64 group -> classifier refuses ->
//!     `base64_decode` fails closed with `Err(())` (no silent partial decode).
//!   * A candidate mixing both alphabets (`+`/`-` together) is ambiguous and is
//!     rejected rather than guessed.
//!   * `is_base64_candidate_byte` membership is exactly `alnum ∪ {+ / = - _}`
//!     for all 256 byte values.
//!
//! HOST-INDEPENDENCE: these all exercise `base64_decode`, the pure
//! classify + `base64_simd` scalar/portable decode path. No Hyperscan/GPU/SIMD
//! accelerator is assumed; the asserted values are the host-independent
//! contract that every backend must reproduce.

use keyhog_scanner::decode::{base64_decode, is_base64_candidate_byte};

// ── standard (+ /) vs url-safe (- _) alphabet parity ─────────────────────────

#[test]
fn std_slash_plus_and_urlsafe_underscore_dash_decode_identical_bytes() {
    // 3-byte payload [0xFF,0xEF,0xBE] encodes to "/+++"" (standard, index-63 `/`
    // + three index-62 `+`) and "_---" (url-safe, index-63 `_` + three
    // index-62 `-`). len 4, len%4==0, no padding.
    let std_form = "/+++";
    let url_form = "_---";
    // The two encoded strings are genuinely different bytes (proving the `-_`
    // vs `+/` alphabet swap is real, not a no-op)...
    assert_ne!(std_form, url_form);
    // ...yet decode to the identical payload.
    assert_eq!(base64_decode(std_form).unwrap(), vec![255u8, 239, 190]);
    assert_eq!(base64_decode(url_form).unwrap(), vec![255u8, 239, 190]);
    assert_eq!(
        base64_decode(std_form).unwrap(),
        base64_decode(url_form).unwrap()
    );
}

#[test]
fn std_and_urlsafe_padded_decode_identical_bytes() {
    // 2-byte payload [0xFB,0xF0] -> "+/A=" (standard) / "-_A=" (url-safe),
    // both len 4 with one `=` pad, len%4==0.
    assert_eq!(base64_decode("+/A=").unwrap(), vec![251u8, 240]);
    assert_eq!(base64_decode("-_A=").unwrap(), vec![251u8, 240]);
    assert_eq!(
        base64_decode("+/A=").unwrap(),
        base64_decode("-_A=").unwrap()
    );
}

#[test]
fn four_variant_forms_of_one_payload_all_decode_to_same_bytes() {
    // The same [0xFB,0xF0] reachable via ALL FOUR classifier variants:
    //   Standard      "+/A=" (len4, padded)
    //   UrlSafe       "-_A=" (len4, padded)
    //   StandardNoPad "+/A"  (len3, %4==3)
    //   UrlSafeNoPad  "-_A"  (len3, %4==3)
    let expected = vec![251u8, 240];
    for form in ["+/A=", "-_A=", "+/A", "-_A"] {
        assert_eq!(
            base64_decode(form).unwrap(),
            expected,
            "variant form {form} must decode to [251,240]"
        );
    }
}

#[test]
fn dash_underscore_alternation_matches_slash_plus_alternation() {
    // [0xFB,0xFF,0xBF] -> "+/+/" (standard) / "-_-_" (url-safe), len4 no pad.
    // Exercises index-62 and index-63 in every position.
    assert_eq!(base64_decode("+/+/").unwrap(), vec![251u8, 255, 191]);
    assert_eq!(base64_decode("-_-_").unwrap(), vec![251u8, 255, 191]);
}

// ── padded / unpadded parity within one alphabet ─────────────────────────────

#[test]
fn standard_padded_and_nopad_decode_identical_bytes() {
    // [0xFF,0xFF] -> "//8=" (padded, len4) vs "//8" (nopad, len3, %4==3).
    assert_eq!(base64_decode("//8=").unwrap(), vec![255u8, 255]);
    assert_eq!(base64_decode("//8").unwrap(), vec![255u8, 255]);
    assert_eq!(
        base64_decode("//8=").unwrap(),
        base64_decode("//8").unwrap()
    );
}

#[test]
fn urlsafe_padded_and_nopad_decode_identical_bytes() {
    // [0xFF,0xFF] -> "__8=" (padded, len4) vs "__8" (nopad, len3, %4==3).
    assert_eq!(base64_decode("__8=").unwrap(), vec![255u8, 255]);
    assert_eq!(base64_decode("__8").unwrap(), vec![255u8, 255]);
    assert_eq!(
        base64_decode("__8=").unwrap(),
        base64_decode("__8").unwrap()
    );
}

// ── length-mod-4 boundary: %4==1 rejects, %4∈{0,2,3} decodes ──────────────────

#[test]
fn length_mod_four_equals_one_fails_closed_standard() {
    // 5-char all-alnum standard run: 5 % 4 == 1 is never a whole base64 group,
    // so the classifier returns None and decode fails closed (no partial bytes).
    assert_eq!(base64_decode("aGVsb"), Err(()));
}

#[test]
fn length_mod_four_equals_one_fails_closed_urlsafe() {
    // url-safe twin: "-_-_-" is 5 chars (%4==1) of url-safe alphabet -> Err.
    assert_eq!(base64_decode("-_-_-"), Err(()));
}

#[test]
fn length_mod_four_zero_two_three_all_decode() {
    // Valid unpadded lengths: %4==0 (full group), %4==2, %4==3 all decode.
    assert_eq!(base64_decode("aGVs").unwrap(), vec![104u8, 101, 108]); // %4==0 -> "hel"
                                                                       // %4==2 must be CANONICAL: the final 2-char group's leftover 4 bits must be
                                                                       // zero. "hell" -> "aGVsbA" (`A`=000000); "aGVsbG" (`G`=000110) is non-canonical
                                                                       // and the strict decoder correctly rejects it.
    assert_eq!(base64_decode("aGVsbA").unwrap(), vec![104u8, 101, 108, 108]); // %4==2 -> "hell"
    assert_eq!(
        base64_decode("aGVsbG8").unwrap(),
        vec![104u8, 101, 108, 108, 111]
    ); // %4==3 -> "hello"
}

// ── mixed-alphabet & malformed-padding: fail closed ──────────────────────────

#[test]
fn mixed_standard_and_urlsafe_alphabet_fails_closed() {
    // Contains both '+' (standard, index 62) and '-' (url-safe, index 62):
    // ambiguous which alphabet, so the classifier refuses rather than guess.
    assert_eq!(base64_decode("AB+CD-EFGH"), Err(()));
}

#[test]
fn mixed_slash_and_underscore_alphabet_fails_closed() {
    // Both '/' (standard index 63) and '_' (url-safe index 63) -> ambiguous.
    assert_eq!(base64_decode("AB/CD_EFGH"), Err(()));
}

#[test]
fn three_or_more_padding_chars_fail_closed() {
    // At most two '=' are legal base64 padding; a run of four is rejected the
    // moment padding_len exceeds 2.
    assert_eq!(base64_decode("QUJD===="), Err(()));
}

#[test]
fn internal_equals_before_padding_fails_closed() {
    // An '=' that is not a trailing pad marks a key=value separator, not base64;
    // "AB=CD" has '=' before any trailing run -> reject.
    assert_eq!(base64_decode("AB=CD"), Err(()));
}

// ── is_base64_candidate_byte: exact membership over the full byte range ───────

#[test]
fn candidate_byte_membership_matches_reference_over_all_256_bytes() {
    // Independent reference: alnum ∪ {+ / = - _}. Assert an exact bool per byte.
    for b in 0u16..=255 {
        let b = b as u8;
        let expected = (b'A'..=b'Z').contains(&b)
            || (b'a'..=b'z').contains(&b)
            || (b'0'..=b'9').contains(&b)
            || b == b'+'
            || b == b'/'
            || b == b'='
            || b == b'-'
            || b == b'_';
        assert_eq!(
            is_base64_candidate_byte(b),
            expected,
            "byte 0x{b:02X} ({:?}) membership",
            b as char
        );
    }
}

#[test]
fn candidate_byte_class_boundaries_are_exact() {
    // ASCII neighbours straddling each accepted class: the accepted byte is IN,
    // its adjacent non-member is OUT. Locks the class edges concretely.
    // '/'(0x2F) in, '.'(0x2E) out; '0'..'9' in, ':'(0x3A) out;
    // '@'(0x40) out, 'A'..'Z' in, '['(0x5B) out;
    // '`'(0x60) out, 'a'..'z' in, '{'(0x7B) out.
    for b in [
        b'+', b'/', b'=', b'-', b'_', b'A', b'Z', b'a', b'z', b'0', b'9',
    ] {
        assert!(is_base64_candidate_byte(b), "0x{b:02X} should be IN");
    }
    for b in [
        b'.', b':', b'@', b'[', b'`', b'{', b' ', b'\t', b'\n', b'*', b'!', b'%', 0x00, 0x7F, 0x80,
        0xFF,
    ] {
        assert!(!is_base64_candidate_byte(b), "0x{b:02X} should be OUT");
    }
}
