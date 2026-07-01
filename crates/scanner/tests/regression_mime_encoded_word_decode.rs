//! Test-depth lock for the RFC2047 MIME encoded-word decoder
//! (`crates/scanner/src/decode/url.rs::mime_encoded_word_decode`), the primitive
//! that unwraps `=?charset?enc?text?=` — the form used to smuggle non-ASCII (and
//! secrets) through email/HAR headers, e.g. `Subject: =?utf-8?B?<base64>?=`.
//!
//! Before this suite the decoder had only a B-happy-path and a Q-underscore
//! test. This pins the full contract: `B` (base64) and `Q` (quoted-printable-
//! like) dispatch, case-insensitive encoding letter, the ignored charset label,
//! `_`→space and `=XX` in Q, the malformed-word rejections (missing `=?`/`?=`,
//! unknown encoding, empty encoding, undecodable payload), and the deliberate
//! strict-UTF-8 reject (a decoded byte sequence that is not valid UTF-8 yields
//! `None`, matching every other decoder in the pipeline).
//!
//! Driven directly through the `keyhog_scanner::testing` facade so each case
//! asserts the exact decoded string, not merely non-emptiness.

#![cfg(feature = "decode")]

use keyhog_scanner::testing::mime_encoded_word_decode_for_test as mime;

fn dec(s: &str) -> String {
    mime(s).expect("well-formed encoded-word decodes")
}

// ── `B` (base64) encoding ────────────────────────────────────────────────────

#[test]
fn mime_b_decodes_base64_ascii() {
    assert_eq!(dec("=?utf-8?B?QUJD?="), "ABC");
}

#[test]
fn mime_b_lowercase_encoding_letter() {
    assert_eq!(dec("=?utf-8?b?QUJD?="), "ABC");
}

#[test]
fn mime_b_charset_label_is_ignored() {
    assert_eq!(dec("=?ISO-8859-1?B?QUJD?="), "ABC");
}

#[test]
fn mime_b_base64_padding_in_payload_decodes() {
    // The `=` padding inside the payload must not be confused with the `?=`
    // closing delimiter (splitn keys on `?`, not `=`).
    assert_eq!(dec("=?utf-8?B?QUI=?="), "AB");
}

#[test]
fn mime_b_multibyte_utf8_payload() {
    // w6k= == base64([0xC3,0xA9]) == "é".
    assert_eq!(dec("=?utf-8?B?w6k=?="), "é");
}

#[test]
fn mime_b_realistic_secret_payload_surfaces() {
    // The recall point: a token hidden in a base64 encoded-word header.
    assert_eq!(dec("=?utf-8?B?c2stc2VjcmV0MTIz?="), "sk-secret123");
}

#[test]
fn mime_b_empty_payload_is_empty_string() {
    assert_eq!(dec("=?utf-8?B??="), "");
}

// ── `Q` (quoted-printable-like) encoding ─────────────────────────────────────

#[test]
fn mime_q_decodes_plain_text() {
    assert_eq!(dec("=?utf-8?Q?Hello?="), "Hello");
}

#[test]
fn mime_q_lowercase_encoding_letter() {
    assert_eq!(dec("=?utf-8?q?Hello?="), "Hello");
}

#[test]
fn mime_q_underscore_becomes_space() {
    assert_eq!(dec("=?utf-8?Q?under_score?="), "under score");
}

#[test]
fn mime_q_hex_octet_decodes() {
    // =42 is 'B'.
    assert_eq!(dec("=?utf-8?Q?A=42C?="), "ABC");
}

#[test]
fn mime_q_hex_space_octet() {
    assert_eq!(dec("=?utf-8?Q?a=20b?="), "a b");
}

#[test]
fn mime_q_mixed_underscore_and_hex() {
    // `_`→space, `=3D`→'='.
    assert_eq!(dec("=?utf-8?Q?a_b=3Dc?="), "a b=c");
}

#[test]
fn mime_q_hex_octet_at_end() {
    assert_eq!(dec("=?utf-8?Q?=41?="), "A");
}

// ── Malformed encoded-words reject (→ None) ──────────────────────────────────

#[test]
fn mime_missing_closing_delimiter_rejected() {
    assert_eq!(mime("=?utf-8?B?QUJD"), None);
}

#[test]
fn mime_missing_opening_delimiter_rejected() {
    assert_eq!(mime("utf-8?B?QUJD?="), None);
}

#[test]
fn mime_unknown_encoding_letter_rejected() {
    assert_eq!(mime("=?utf-8?X?QUJD?="), None);
}

#[test]
fn mime_too_short_input_rejected() {
    // len < 4: the `=?` opener and `?=` closer would overlap.
    assert_eq!(mime("=?="), None);
}

#[test]
fn mime_empty_inner_missing_encoding_rejected() {
    assert_eq!(mime("=??="), None);
}

#[test]
fn mime_invalid_base64_payload_rejected() {
    assert_eq!(mime("=?utf-8?B?@@@@?="), None);
}

#[test]
fn mime_invalid_hex_in_q_rejected() {
    assert_eq!(mime("=?utf-8?Q?=ZZ?="), None);
}

// ── Boundary: strict-UTF-8 reject + minimal charset ──────────────────────────

#[test]
fn mime_q_non_utf8_bytes_rejected() {
    // =FF decodes to the single byte 0xFF, which is not valid UTF-8; the whole
    // word is rejected, matching every other decoder's strict-UTF-8 contract.
    assert_eq!(mime("=?ISO-8859-1?Q?=FF?="), None);
}

#[test]
fn mime_single_char_charset_label() {
    assert_eq!(dec("=?a?B?QUJD?="), "ABC");
}
