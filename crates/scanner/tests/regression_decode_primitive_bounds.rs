//! Regression: exact-value bounds for the decode primitives under
//! `crates/scanner/src/decode` (base64 / hex / z85 / reverse) and the pre-decode
//! extractor's freestanding-run floor.
//!
//! Every assertion pins a CONCRETE expected value, exact decoded bytes, exact
//! candidate strings/spans, exact `Err(())`, exact booleans, not shape. The
//! decoders are the front door of decode-through scanning: a silent drift in
//! the base64 variant classifier, the hex underscore-tolerance, the z85 frame
//! math, the extractor's 16-char freestanding floor, or the reverse-decode
//! admission gate (`MIN_REVERSE_PREFIX_LEN`) is a recall or precision bug, so
//! each is locked to its computed value here.

use keyhog_scanner::decode::{
    base64_decode, find_base64_strings, find_hex_strings, hex_decode, is_base64_candidate_byte,
    z85_decode,
};
use keyhog_scanner::testing::{
    extract_encoded_value_spans_for_test as extract_spans, looks_reversible_for_test,
    reverse_str_for_test,
};

// ── base64 primitive: exact decoded bytes ───────────────────────────────────

#[test]
fn base64_standard_padded_decodes_to_hello() {
    // "hello" -> standard base64 with trailing '=' padding (len 8, len%4==0).
    assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello".to_vec());
}

#[test]
fn base64_standard_nopad_decodes_to_hello() {
    // Same "hello" body without the '=' pad (len 7, len%4==3) routes through the
    // STANDARD_NO_PAD variant and must yield the identical bytes.
    assert_eq!(base64_decode("aGVsbG8").unwrap(), b"hello".to_vec());
}

#[test]
fn base64_embedded_pem_private_key_is_surfaced() {
    // base64 of a PEM RSA private key block. Decode-through must recover the
    // literal PEM header bytes so the private-key detector can anchor on
    // "-----BEGIN". Assert the exact decoded string, not just presence.
    let b64 = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlCT2dJQkFBSkJBS2ozNEdreEZoRDkwdmNOTFlMSW5GRVg2UHB5MXRQZjlDbnpqNHA0V0dlS0xzMVB0OFF1Ci0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0t";
    let decoded = String::from_utf8(base64_decode(b64).unwrap()).unwrap();
    let expected = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----";
    assert_eq!(decoded, expected);
    // And the whole blob is extracted as exactly one base64 candidate so the
    // decode-through pass reaches it (the "surfaced" half of the contract).
    let cands: Vec<String> = find_base64_strings(b64, 16)
        .into_iter()
        .map(|e| e.value)
        .collect();
    assert_eq!(cands, vec![b64.to_string()]);
}

#[test]
fn base64_internal_equals_is_rejected() {
    // A '=' before the trailing padding run is an assignment separator, not
    // base64 padding: the classifier returns None and decode fails closed.
    assert_eq!(base64_decode("QUtJ=QUlP"), Err(()));
}

#[test]
fn base64_leading_equals_is_rejected() {
    // '=' at index 0 can never be padding; scan_base64_candidate bails.
    assert_eq!(base64_decode("=QUtJQUlP"), Err(()));
}

#[test]
fn base64_mixed_standard_and_urlsafe_alphabet_is_rejected() {
    // Contains both '+' (standard) and '-' (url-safe): an ambiguous alphabet
    // the classifier refuses rather than guessing a variant.
    assert_eq!(base64_decode("aa+bb-ccddeeff"), Err(()));
}

#[test]
fn is_base64_candidate_byte_covers_exact_alphabet() {
    // The single canonical base64/url-safe alphabet predicate: alnum + the six
    // symbol bytes are IN, everything else is OUT.
    for b in [b'A', b'z', b'0', b'+', b'/', b'=', b'-', b'_'] {
        assert!(
            is_base64_candidate_byte(b),
            "expected {} in alphabet",
            b as char
        );
    }
    for b in [b' ', b'*', b'.', b'\n', b'!', b'%'] {
        assert!(
            !is_base64_candidate_byte(b),
            "expected {} out of alphabet",
            b as char
        );
    }
}

// ── hex primitive: exact decoded bytes + boundary rejects ────────────────────

#[test]
fn hex_decodes_to_hello() {
    assert_eq!(hex_decode("68656c6c6f").unwrap(), b"hello".to_vec());
}

#[test]
fn hex_underscore_separated_decodes_to_hello() {
    // Firmware/config hex often groups bytes with '_'; the decoder strips them
    // (audit class #5) and yields the identical bytes.
    assert_eq!(hex_decode("68_65_6c_6c_6f").unwrap(), b"hello".to_vec());
}

#[test]
fn hex_odd_length_is_rejected() {
    // Odd digit count is not a whole number of bytes: fail closed.
    assert_eq!(hex_decode("686"), Err(()));
}

#[test]
fn hex_non_hex_byte_is_rejected() {
    assert_eq!(hex_decode("68zz"), Err(()));
}

// ── z85 primitive: exact frame math ──────────────────────────────────────────

#[test]
fn z85_decodes_helloworld_reference_frame() {
    // Canonical RFC 32/Z85 test vector: "HelloWorld" <-> the 8-byte frame.
    assert_eq!(
        z85_decode("HelloWorld").unwrap(),
        vec![134u8, 79, 210, 111, 181, 89, 247, 91]
    );
}

#[test]
fn z85_non_multiple_of_five_is_rejected() {
    // Z85 encodes 5 chars per 4 bytes; a length not divisible by 5 is invalid.
    assert_eq!(z85_decode("abcd"), Err(()));
}

// ── extractor + find_*: sub-threshold runs are NOT candidates ────────────────

#[test]
fn freestanding_run_below_sixteen_is_not_extracted() {
    // A freestanding 15-char base64-alphabet run is under the 16-char
    // MIN_B64_BLOCK_LEN floor and must produce zero extraction candidates.
    let spans = extract_spans("QUtJQUlPU0ZPRE5");
    assert_eq!(spans, Vec::<(String, usize, usize)>::new());
}

#[test]
fn freestanding_run_at_sixteen_is_extracted_with_exact_span() {
    // At exactly 16 chars the run clears the floor and is emitted as one
    // candidate spanning bytes 0..16 with the exact value.
    let spans = extract_spans("QUtJQUlPU0ZPRE5O");
    assert_eq!(
        spans,
        vec![("QUtJQUlPU0ZPRE5O".to_string(), 0usize, 16usize)]
    );
}

#[test]
fn find_base64_respects_min_length_threshold() {
    // A 20-char valid base64 blob: filtered out when min_length exceeds its
    // length, surfaced (exact value) when min_length is at or below it.
    let blob = "QUtJQUlPU0ZPRE5ON0VY";
    let above: Vec<String> = find_base64_strings(blob, 24)
        .into_iter()
        .map(|e| e.value)
        .collect();
    assert_eq!(above, Vec::<String>::new());
    let at: Vec<String> = find_base64_strings(blob, 16)
        .into_iter()
        .map(|e| e.value)
        .collect();
    assert_eq!(at, vec![blob.to_string()]);
}

#[test]
fn find_hex_respects_min_length_threshold() {
    // 16 hex chars: not a candidate at min_length 18, exact candidate at 16.
    let blob = "68656c6c6f68656c";
    let above: Vec<String> = find_hex_strings(blob, 18)
        .into_iter()
        .map(|e| e.value)
        .collect();
    assert_eq!(above, Vec::<String>::new());
    let at: Vec<String> = find_hex_strings(blob, 16)
        .into_iter()
        .map(|e| e.value)
        .collect();
    assert_eq!(at, vec![blob.to_string()]);
}

// ── reverse decoder admission gate (MIN_REVERSE_PREFIX_LEN) ───────────────────

#[test]
fn reverse_str_reverses_by_scalar() {
    assert_eq!(reverse_str_for_test("abcXYZ"), "ZYXcba");
    assert_eq!(reverse_str_for_test("AKIA1234"), "4321AIKA");
}

#[test]
fn reversed_known_prefix_is_admitted() {
    // `AKIA-64ABDEFSEWKRUMSEK1NR` reversed. It carries a 12+ alnum run and
    // contains reverse("AKIA")=="AIKA", so the reverse decoder admits it.
    assert!(looks_reversible_for_test("RNK1ESEMURKWESFEDBA-46AIKA"));
}

#[test]
fn long_alnum_run_without_reversed_prefix_is_rejected() {
    // reverse("ABC..Z"), a 26-char alnum run but no reversed provider prefix,
    // so it must NOT be treated as a reverse-encoded credential.
    assert!(!looks_reversible_for_test("ZYXWVUTSRQPONMLKJIHGFEDCBA"));
}

#[test]
fn two_char_prefix_0x_is_below_min_reverse_prefix_len() {
    // Ends with "x0" == reverse("0x"). The 2-char "0x" prefix is deliberately
    // EXCLUDED from the reverse gate (MIN_REVERSE_PREFIX_LEN == 3), so even with
    // a 16-char alnum run this stays out.
    assert!(!looks_reversible_for_test("ABCDEFGHIJKLMNx0"));
}

#[test]
fn three_char_prefix_hf_is_admitted() {
    // Ends with "_fh" == reverse("hf_"), a 3-char vendor prefix that still gates.
    // Same 12+ alnum run as the 0x case, so the ONLY difference is the prefix
    // length crossing MIN_REVERSE_PREFIX_LEN (this one is admitted).
    assert!(looks_reversible_for_test("ABCDEFGHIJKL_fh"));
}
