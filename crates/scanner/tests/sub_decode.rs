//! Standalone unit coverage for `keyhog_scanner::decode` public functions:
//! base64 / hex / z85 round-trips and the Caesar/reverse evasion predicates.
//!
//! Asserts exact decoded BYTES (round-trip identity), exact reject behaviour on
//! malformed input, and the precise boolean gates the decode pipeline relies on
//! — never `is_ok`/`is_empty` decoration.

use keyhog_scanner::decode::caesar::{
    caesar_shift, candidate_shape_invariant, is_source_code_path, looks_credential_shaped,
    matched_caesar_shifts, MIN_CAESAR_LEN,
};
use keyhog_scanner::decode::hex::find_hex_strings;
use keyhog_scanner::decode::reverse::{looks_reversible, reverse_str};
use keyhog_scanner::decode::{base64_decode, find_base64_strings, hex_decode, z85_decode};

// ---------------------------------------------------------------------------
// base64_decode — exact bytes, variant handling, reject on malformed
// ---------------------------------------------------------------------------

#[test]
fn base64_standard_decodes_to_exact_bytes() {
    // "Man" -> "TWFu" (the canonical base64 RFC example).
    assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
    // "Hello, World!" padded.
    assert_eq!(
        base64_decode("SGVsbG8sIFdvcmxkIQ==").unwrap(),
        b"Hello, World!"
    );
}

#[test]
fn base64_urlsafe_decodes_distinct_from_standard() {
    // 0xFB 0xFF 0xBF encodes to "-_-_" url-safe (uses - and _ instead of + /).
    let decoded = base64_decode("-_-_").unwrap();
    assert_eq!(decoded, vec![0xFBu8, 0xFF, 0xBF]);
}

#[test]
fn base64_mixed_alphabet_is_rejected() {
    // Contains BOTH a standard (+) and a url-safe (-) char: ambiguous -> Err.
    assert!(base64_decode("ab+c-def").is_err());
}

#[test]
fn base64_bad_padding_is_rejected() {
    // '=' in the interior is invalid padding placement.
    assert!(base64_decode("AB=C").is_err());
    // Leading '=' (first_padding == 0) is invalid.
    assert!(base64_decode("=AAA").is_err());
}

#[test]
fn base64_roundtrip_credential_shape() {
    use base64::Engine;
    let secret = b"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";
    let encoded = base64::engine::general_purpose::STANDARD.encode(secret);
    assert_eq!(base64_decode(&encoded).unwrap(), secret);
}

#[test]
fn find_base64_strings_extracts_blob_over_floor() {
    use base64::Engine;
    let blob = base64::engine::general_purpose::STANDARD.encode([0x55u8; 30]); // 40 chars
    let text = format!("token = \"{}\"", blob);
    let found = find_base64_strings(&text, 12);
    assert!(
        found.iter().any(|e| e.value == blob),
        "expected to extract {} from {:?}",
        blob,
        found.iter().map(|e| &e.value).collect::<Vec<_>>()
    );
}

#[test]
fn find_base64_strings_respects_min_length() {
    // "TWFu" is valid base64 but only 4 chars; a min_length of 12 drops it.
    let found = find_base64_strings("x = TWFu", 12);
    assert!(found.iter().all(|e| e.value != "TWFu"));
}

// ---------------------------------------------------------------------------
// hex_decode + find_hex_strings
// ---------------------------------------------------------------------------

#[test]
fn hex_decodes_to_exact_bytes() {
    assert_eq!(hex_decode("48656c6c6f").unwrap(), b"Hello");
    assert_eq!(hex_decode("00ff10").unwrap(), vec![0x00u8, 0xFF, 0x10]);
}

#[test]
fn hex_decode_strips_underscores() {
    // Firmware-style `_`-separated hex must decode identically to the joined form.
    assert_eq!(hex_decode("48_65_6c_6c_6f").unwrap(), b"Hello");
}

#[test]
fn hex_decode_odd_length_is_rejected() {
    assert!(hex_decode("abc").is_err());
}

#[test]
fn hex_decode_non_hex_is_rejected() {
    assert!(hex_decode("zzzz").is_err());
}

#[test]
fn find_hex_strings_finds_long_hex_run() {
    // 32 hex chars (16 bytes), above the 16-char floor.
    let hexs = "deadbeefcafebabe0011223344556677";
    let text = format!("key={}", hexs);
    let found = find_hex_strings(&text, 16);
    assert!(
        found.iter().any(|e| e.value == hexs),
        "expected {} in extracted set",
        hexs
    );
}

// ---------------------------------------------------------------------------
// z85_decode — round-trip against a known Z85 fixture
// ---------------------------------------------------------------------------

#[test]
fn z85_decodes_known_vector() {
    // ZeroMQ Z85 spec example: bytes 0x86 0x4F 0xD2 0x6F 0xB5 0x59 0xF7 0x5B
    // encode to "HelloWorld".
    let decoded = z85_decode("HelloWorld").unwrap();
    assert_eq!(
        decoded,
        vec![0x86u8, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B]
    );
}

#[test]
fn z85_non_multiple_of_five_is_rejected() {
    assert!(z85_decode("Hello1").is_err()); // 6 chars, not a multiple of 5
}

// ---------------------------------------------------------------------------
// caesar_shift — exact rotation, wrap, identity, full cycle
// ---------------------------------------------------------------------------

#[test]
fn caesar_shift_rot13_known() {
    assert_eq!(caesar_shift("AKIA", 13), "NXVN");
    assert_eq!(caesar_shift("Hello", 13), "Uryyb");
}

#[test]
fn caesar_shift_preserves_digits_and_punct() {
    // Digits and punctuation are identity under any shift.
    assert_eq!(caesar_shift("abc-123_XYZ", 1), "bcd-123_YZA");
}

#[test]
fn caesar_shift_full_cycle_is_identity() {
    let s = "TheQuickBrownFox";
    // 26 shifts returns to the original.
    let mut acc = s.to_string();
    for _ in 0..26 {
        acc = caesar_shift(&acc, 1);
    }
    assert_eq!(acc, s);
}

#[test]
fn caesar_shift_inverts() {
    let s = "Credential9";
    // shift k then shift (26-k) returns the original.
    assert_eq!(caesar_shift(&caesar_shift(s, 7), 19), s);
}

// ---------------------------------------------------------------------------
// matched_caesar_shifts — exactness vs the brute-force shift set
// ---------------------------------------------------------------------------

#[test]
fn matched_shifts_recovers_planted_prefix_shift() {
    // Plant a ghp_ token shifted by +5; the matched-shift table must mark the
    // INVERSE shift (21) which decodes it back to a KNOWN_PREFIXES form.
    let plain = "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";
    let shifted = caesar_shift(plain, 5);
    let try_shift = matched_caesar_shifts(&shifted);
    // Decoding `shifted` by 21 == caesar_shift(.,26-5) yields the plaintext.
    assert!(
        try_shift[21],
        "shift 21 (inverse of +5) must be selected so ghp_ re-surfaces"
    );
    assert_eq!(caesar_shift(&shifted, 21), plain);
}

#[test]
fn matched_shifts_is_superset_of_credential_shaped_brute_force() {
    // Differential: for any candidate, every shift that produces a
    // credential-shaped string MUST be present in the matched-shift table
    // (the table is a recall-exact selection, never dropping a true shift).
    let candidates = [
        caesar_shift("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", 3),
        caesar_shift("AKIAIOSFODNN7EXAMPLE1234", 9),
        "nothinghere0000".to_string(),
    ];
    for cand in &candidates {
        let table = matched_caesar_shifts(cand);
        for k in 1..=25u8 {
            let decoded = caesar_shift(cand, k);
            if looks_credential_shaped(&decoded) {
                assert!(
                    table[k as usize],
                    "shift {} is credential-shaped for {:?} but not in the matched table",
                    k, cand
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// candidate_shape_invariant / looks_credential_shaped
// ---------------------------------------------------------------------------

#[test]
fn shape_invariant_requires_digit_letter_and_run() {
    // Has digit + letter + an 8+ alnum run.
    assert!(candidate_shape_invariant("abcdefgh1"));
    // No digit -> false (digits are shift-invariant, so no shift can add one).
    assert!(!candidate_shape_invariant("abcdefghij"));
    // No letter -> false.
    assert!(!candidate_shape_invariant("123456789"));
    // Run broken by punctuation under 8 -> false.
    assert!(!candidate_shape_invariant("ab-cd-1f-gh"));
}

#[test]
fn looks_credential_shaped_needs_known_prefix() {
    // ghp_ with digits and a long run -> shaped.
    assert!(looks_credential_shaped(
        "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"
    ));
    // Long alnum run + digit but no known provider prefix -> NOT shaped.
    assert!(!looks_credential_shaped("zzzzzzzzzz12345678"));
}

#[test]
fn min_caesar_len_constant_is_sixteen() {
    assert_eq!(MIN_CAESAR_LEN, 16);
}

// ---------------------------------------------------------------------------
// is_source_code_path
// ---------------------------------------------------------------------------

#[test]
fn source_code_paths_detected() {
    assert!(is_source_code_path(Some("src/main.rs")));
    assert!(is_source_code_path(Some("a/b/Service.java")));
    assert!(is_source_code_path(Some("Makefile")));
    assert!(is_source_code_path(Some("CMakeLists.txt")));
    assert!(is_source_code_path(Some("README.md")));
}

#[test]
fn non_source_paths_not_detected() {
    assert!(!is_source_code_path(Some(".env")));
    assert!(!is_source_code_path(Some("k8s/secret.yaml")));
    assert!(!is_source_code_path(None));
}

// ---------------------------------------------------------------------------
// reverse_str / looks_reversible
// ---------------------------------------------------------------------------

#[test]
fn reverse_str_is_an_involution() {
    let s = "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";
    assert_eq!(reverse_str(&reverse_str(s)), s);
    assert_eq!(reverse_str("abc"), "cba");
}

#[test]
fn looks_reversible_true_when_reverse_holds_known_prefix() {
    // Reverse of a ghp_ token: reversing it back contains the ghp_ prefix, so
    // the reversed blob is a worthwhile decode candidate.
    let plain = "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";
    let reversed = reverse_str(plain);
    assert!(
        looks_reversible(&reversed),
        "reversed ghp_ token should be flagged reversible"
    );
}

#[test]
fn looks_reversible_false_for_plain_prose_run() {
    // A long alnum run whose reverse holds no known provider prefix.
    assert!(!looks_reversible("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
    // Too short to bother.
    assert!(!looks_reversible("short"));
}
