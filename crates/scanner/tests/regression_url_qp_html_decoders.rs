//! Regression coverage for the scanner's percent/URL, quoted-printable,
//! octal-escape, MIME encoded-word and HTML-entity decode-through paths
//! (`crates/scanner/src/decode/url.rs`).
//!
//! Every assertion pins the EXACT decoded bytes a wrapped secret produces, plus
//! the exact left/handled behaviour of a malformed escape. Two seams are used:
//!   * the `*_for_test` facades (`quoted_printable_decode_for_test`,
//!     `octal_escape_decode_for_test`, `mime_encoded_word_decode_for_test`)
//!     return the decoder's exact `Option<String>`;
//!   * `testing::decode_chunk` drives the full pipeline so the percent/URL and
//!     HTML-entity decoders (which have no direct facade) are exercised end to
//!     end and the decoded layer's bytes are asserted.
#![cfg(feature = "decode")]

use keyhog_core::Chunk;
use keyhog_scanner::testing::{
    decode_chunk, mime_encoded_word_decode_for_test, octal_escape_decode_for_test,
    quoted_printable_decode_for_test,
};

/// Run the whole decode pipeline over `text` and return the `data` of every
/// emitted layer whose `source_type` names `decoder` (e.g. `"url"`,
/// `"html-named-entity"`). Depth 2 admits the chunk-level candidate extraction.
fn layers_for(text: &str, decoder: &str) -> Vec<String> {
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    decode_chunk(&chunk, 2, false, None, None)
        .into_iter()
        .filter(|c| c.metadata.source_type.contains(decoder))
        .map(|c| c.data.to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Quoted-printable `=XX` (facade → exact Option<String>)
// ---------------------------------------------------------------------------

#[test]
fn qp_hex_octets_decode_to_exact_bytes() {
    // `=41=42=43` are the QP octets for the ASCII bytes 0x41/0x42/0x43.
    assert_eq!(
        quoted_printable_decode_for_test("=41=42=43"),
        Some("ABC".to_string())
    );
}

#[test]
fn qp_encoded_equals_3d_decodes_to_literal_equals() {
    // A literal `=` is always QP-encoded `=3D` (0x3D); it must round-trip back
    // to `=`, keeping a `key=value` secret contiguous after decode.
    assert_eq!(
        quoted_printable_decode_for_test("secret=3Dvalue"),
        Some("secret=value".to_string())
    );
}

#[test]
fn qp_soft_line_break_crlf_is_removed() {
    // `=\r\n` is a QP soft line break: the `=` and the CRLF are dropped so a
    // secret an encoder wrapped across the break stays one contiguous run.
    assert_eq!(
        quoted_printable_decode_for_test("AKIA=\r\nREST"),
        Some("AKIAREST".to_string())
    );
}

#[test]
fn qp_soft_line_break_bare_lf_is_removed() {
    // Real-world (Unix-origin) QP also emits a bare `=\n` soft break.
    assert_eq!(
        quoted_printable_decode_for_test("a=\nb"),
        Some("ab".to_string())
    );
}

#[test]
fn qp_trailing_equals_is_literal() {
    // A `=` that is the final byte (no octet, no newline) is a literal `=`.
    assert_eq!(
        quoted_printable_decode_for_test("end="),
        Some("end=".to_string())
    );
}

#[test]
fn qp_non_hex_after_equals_is_literal() {
    // `=Z` is not a hex octet: the `=` is kept literal and the `Z`s copy
    // through unchanged, so the whole candidate is preserved (not dropped).
    assert_eq!(
        quoted_printable_decode_for_test("=ZZ"),
        Some("=ZZ".to_string())
    );
}

#[test]
fn qp_underscore_is_not_converted_to_space() {
    // The `_`->space rule is MIME Q-encoding, NOT plain quoted-printable; a `_`
    // must survive verbatim in the QP decoder.
    assert_eq!(
        quoted_printable_decode_for_test("a_b"),
        Some("a_b".to_string())
    );
}

// ---------------------------------------------------------------------------
// C-style octal `\NNN` (facade → exact Option<String>)
// ---------------------------------------------------------------------------

#[test]
fn octal_three_digit_escapes_decode_to_exact_bytes() {
    // `\101\102\103` are the octal escapes for 0o101/0o102/0o103 = A/B/C.
    assert_eq!(
        octal_escape_decode_for_test("\\101\\102\\103"),
        Some("ABC".to_string())
    );
}

#[test]
fn octal_escape_is_greedy_but_capped_at_three_digits() {
    // `\1011` = the 3-digit escape `\101` (=A) followed by a literal `1`.
    assert_eq!(
        octal_escape_decode_for_test("\\1011"),
        Some("A1".to_string())
    );
    // A short escape terminated by a non-octal char decodes then continues.
    assert_eq!(
        octal_escape_decode_for_test("\\101x"),
        Some("Ax".to_string())
    );
}

#[test]
fn octal_value_above_0o377_wraps_mod_256() {
    // `\777` = 0o777 = 511, which wraps mod 256 to 255 -> U+00FF ('ÿ').
    assert_eq!(
        octal_escape_decode_for_test("\\777"),
        Some("\u{00FF}".to_string())
    );
}

#[test]
fn octal_backslash_not_followed_by_octal_digit_decodes_nothing() {
    // `\9` is a literal backslash + '9'; no octal escape triggers, so the
    // decoder reports "nothing decoded" (None), never a spurious byte.
    assert_eq!(octal_escape_decode_for_test("\\9"), None);
}

#[test]
fn octal_trailing_backslash_is_kept_literal_after_a_valid_escape() {
    // `\101\` = A followed by a trailing literal backslash. Earlier code
    // returned Err on the trailing `\`, dropping the already-decoded A; the
    // fixed decoder keeps both.
    assert_eq!(
        octal_escape_decode_for_test("\\101\\"),
        Some("A\\".to_string())
    );
}

// ---------------------------------------------------------------------------
// MIME RFC2047 encoded-word (facade → exact Option<String>)
// ---------------------------------------------------------------------------

#[test]
fn mime_base64_encoded_word_decodes_secret() {
    // `c2VjcmV0` is standard base64 for "secret".
    assert_eq!(
        mime_encoded_word_decode_for_test("=?utf-8?B?c2VjcmV0?="),
        Some("secret".to_string())
    );
}

#[test]
fn mime_q_encoded_word_applies_underscore_space_and_hex() {
    // Q-encoding: `_`->space and `=21` -> 0x21 ('!').
    assert_eq!(
        mime_encoded_word_decode_for_test("=?utf-8?Q?hello_world=21?="),
        Some("hello world!".to_string())
    );
}

#[test]
fn mime_unknown_encoding_letter_is_rejected() {
    // Only `B`/`b` (base64) and `Q`/`q` (quoted) are valid; `Z` -> None.
    assert_eq!(mime_encoded_word_decode_for_test("=?utf-8?Z?abc?="), None);
}

#[test]
fn mime_word_shorter_than_four_bytes_is_rejected() {
    // `=?=` is 3 bytes: the `=?` opener and `?=` closer overlap, which the
    // length guard rejects instead of panicking on a reversed slice.
    assert_eq!(mime_encoded_word_decode_for_test("=?="), None);
}

// ---------------------------------------------------------------------------
// Percent/URL `%XX` (pipeline → exact decoded layer bytes)
// ---------------------------------------------------------------------------

#[test]
fn url_percent_escapes_decode_wrapped_secret_to_exact_bytes() {
    // `%41%42%43` = A/B/C, so the quoted candidate decodes to "ABCsecret".
    let layers = layers_for("token = \"%41%42%43secret\"", "url");
    assert!(
        layers.iter().any(|d| d.contains("ABCsecret")),
        "url decoder must emit a layer containing the exact decoded secret; got {layers:?}"
    );
    // The raw percent-escape must NOT survive in the decoded layer.
    assert!(
        layers.iter().all(|d| !d.contains("%41")),
        "decoded url layer must not still contain the %41 escape; got {layers:?}"
    );
}

#[test]
fn url_malformed_first_escape_decodes_valid_neighbor_best_effort() {
    // BEST-EFFORT decoder (decode/url.rs): a malformed `%zz` is copied through
    // as a literal byte, NOT an abort. Because the candidate still contains a
    // VALID `%41` escape, `url_decode` proceeds (it refuses only when NO valid
    // `%XX` exists anywhere — see the HTML/QP negative twins) and emits exactly
    // one url layer with `%41` decoded to 'A'. The old all-or-nothing contract
    // (abort at the first malformed escape → zero layers) was deliberately
    // replaced so a real secret next to a stray `%` is still recovered.
    let malformed = layers_for("token = \"%zz%41value\"", "url");
    assert_eq!(
        malformed.len(),
        1,
        "one best-effort url layer (valid %41 decodes despite the malformed %zz); got {malformed:?}"
    );
    assert!(
        malformed[0].contains("Avalue") && !malformed[0].contains("%41"),
        "the valid %41 escape must decode to 'A' past the literal %zz; got {malformed:?}"
    );
    // Negative twin: the same shape with a valid first escape DOES decode.
    let valid = layers_for("token = \"%41%42%43value\"", "url");
    assert!(
        valid.iter().any(|d| d.contains("ABCvalue")),
        "valid percent-escapes must decode to ABCvalue; got {valid:?}"
    );
}

// ---------------------------------------------------------------------------
// HTML entities `&#NN;` / `&#xNN;` / `&name;` (pipeline → exact layer bytes)
// ---------------------------------------------------------------------------

#[test]
fn html_numeric_decimal_and_hex_entities_decode_to_exact_bytes() {
    // `&#65;` = 'A' (decimal), `&#x42;` = 'B' (hex).
    let layers = layers_for("token = \"&#65;&#x42;end\"", "html-numeric-entity");
    assert!(
        layers.iter().any(|d| d.contains("ABend")),
        "numeric entities must decode to ABend; got {layers:?}"
    );
    assert!(
        layers.iter().all(|d| !d.contains("&#65")),
        "decoded layer must not still contain the raw &#65 entity; got {layers:?}"
    );
}

#[test]
fn html_named_entities_decode_to_exact_bytes() {
    // `&amp;`/`&lt;`/`&gt;` decode to `&`/`<`/`>`.
    let layers = layers_for("token = \"&amp;&lt;&gt;done\"", "html-named-entity");
    assert!(
        layers.iter().any(|d| d.contains("&<>done")),
        "named entities must decode to &<>done; got {layers:?}"
    );
}

#[test]
fn html_unknown_named_entity_emits_no_named_layer() {
    // `&foobar;` is not a recognised named entity, so nothing decodes and no
    // html-named-entity layer is emitted (exact count 0).
    let layers = layers_for("token = \"&foobar;xyz\"", "html-named-entity");
    assert_eq!(
        layers.len(),
        0,
        "unknown named entity must yield zero html-named-entity layers; got {layers:?}"
    );
}
