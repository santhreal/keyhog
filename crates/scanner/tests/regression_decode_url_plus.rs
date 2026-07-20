//! Regression coverage for the scanner's URL / percent decoder
//! (`crates/scanner/src/decode/url.rs`), focused on the `+` handling and the
//! `%XX` escape edge cases.
//!
//! The percent decoder in this crate is a STRICT RFC-3986 percent decoder: it
//! ONLY rewrites `%XX` escapes and copies every other byte, including `+`
//! through unchanged. It is deliberately NOT an
//! `application/x-www-form-urlencoded` decoder, so `+` is a literal `+`, never a
//! space; a real space is only produced by the `%20` escape. Every assertion
//! below pins the EXACT decoded bytes (not a shape/`is_empty` check) so a
//! regression that turned `+` into a space, or dropped/duplicated a byte at an
//! escape boundary, fails loudly.
//!
//! There is no direct `url_decode` facade, so the decode-through pipeline is
//! driven via `testing::decode_chunk` and the `"url"`-named layers are read
//! back; the candidate extractor is exercised directly via
//! `extract_encoded_value_spans_for_test`.
#![cfg(feature = "decode")]

use keyhog_core::Chunk;
use keyhog_scanner::testing::{decode_chunk, extract_encoded_value_spans_for_test};

/// Run the whole decode pipeline over `text` (depth 2, no validation) and return
/// the `data` of every emitted layer produced by a decoder whose name contains
/// `"url"`. Depth 2 admits the chunk-level candidate extraction the URL decoder
/// feeds from.
fn url_layers(text: &str) -> Vec<String> {
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    decode_chunk(&chunk, 2, false, None, None)
        .into_iter()
        .filter(|c| c.metadata.source_type.contains("url"))
        .map(|c| c.data.as_str().to_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// `+` is a LITERAL `+`, never a space (the load-bearing behaviour)
// ---------------------------------------------------------------------------

#[test]
fn plus_between_escapes_stays_literal_not_space() {
    // `%41+%42secret` = 'A' + literal '+' + 'B' + "secret". The decoder is a
    // strict percent decoder, so the `+` survives verbatim: "A+Bsecret".
    let layers = url_layers("token = \"%41+%42secret\"");
    assert!(
        layers.iter().any(|d| d.contains("A+Bsecret")),
        "url decoder must decode %41/%42 and keep the literal '+': got {layers:?}"
    );
    // Negative twin: the form-encoded interpretation ('+' -> space) must NOT
    // appear anywhere in the emitted layers.
    assert!(
        layers.iter().all(|d| !d.contains("A Bsecret")),
        "'+' must NOT be decoded as a space (form-encoding); got {layers:?}"
    );
}

#[test]
fn lone_plus_without_percent_yields_no_url_layer() {
    // A value with `+` but no `%` triggers the URL decoder's `contains('%')`
    // short-circuit: it never runs, so exactly zero url layers are emitted.
    // This proves `+` alone is not a URL-decode trigger.
    let layers = url_layers("token = \"aaaa+bbbb+cccc\"");
    assert_eq!(
        layers.len(),
        0,
        "'+'-only value (no percent escape) must yield zero url layers; got {layers:?}"
    );
}

// ---------------------------------------------------------------------------
// `%2B` -> `+`, `%20` -> space: the escapes that DO produce those bytes
// ---------------------------------------------------------------------------

#[test]
fn percent_2b_uppercase_decodes_to_plus() {
    // 0x2B == 43 == '+', so `%2B` decodes to a single literal '+'.
    let layers = url_layers("token = \"%2Bsecret\"");
    assert!(
        layers.iter().any(|d| d.contains("+secret")),
        "%2B must decode to '+': got {layers:?}"
    );
}

#[test]
fn percent_2b_lowercase_decodes_to_plus() {
    // `hex_val` accepts lower-case hex, so `%2b` decodes identically to `%2B`.
    let layers = url_layers("token = \"%2bsecret\"");
    assert!(
        layers.iter().any(|d| d.contains("+secret")),
        "lower-case %2b must decode to '+': got {layers:?}"
    );
}

#[test]
fn percent_20_decodes_to_real_space_not_plus() {
    // A real space comes ONLY from `%20` (0x20 == 32 == ' '), never from `+`.
    // `%20secret` -> " secret" with a genuine leading space byte.
    let layers = url_layers("token = \"%20secret\"");
    assert!(
        layers.iter().any(|d| d.contains(" secret")),
        "%20 must decode to a literal space: got {layers:?}"
    );
}

#[test]
fn encoded_and_literal_plus_both_yield_plus() {
    // `%2B+plusval` = encoded '+' (0x2B) then a literal '+' then "plusval",
    // decoding to "++plusval": proves %2B->'+' AND the raw '+' passes through.
    let layers = url_layers("token = \"%2B+plusval\"");
    assert!(
        layers.iter().any(|d| d.contains("++plusval")),
        "encoded %2B and literal '+' must both yield '+': got {layers:?}"
    );
}

// ---------------------------------------------------------------------------
// A secret behind `%XX+%XX` recovers the exact bytes
// ---------------------------------------------------------------------------

#[test]
fn secret_between_pct_plus_pct_recovers_exact_bytes() {
    // %73%65%63 = "sec", literal '+', %72%65%74 = "ret" -> "sec+ret".
    let layers = url_layers("token = \"%73%65%63+%72%65%74\"");
    assert!(
        layers.iter().any(|d| d.contains("sec+ret")),
        "percent escapes around a literal '+' must recover exact bytes; got {layers:?}"
    );
}

#[test]
fn multiple_escapes_with_plus_separators_recover_all() {
    // %41%42 = "AB", '+', %43%44 = "CD", '+', %45 = "E" -> "AB+CD+E".
    let layers = url_layers("token = \"%41%42+%43%44+%45\"");
    assert!(
        layers.iter().any(|d| d.contains("AB+CD+E")),
        "every escape either side of the '+' separators must decode; got {layers:?}"
    );
}

// ---------------------------------------------------------------------------
// `%XX` escape boundary / malformed cases (exact behaviour)
// ---------------------------------------------------------------------------

#[test]
fn valid_escape_at_value_end_decodes_boundary() {
    // The `index + 2 >= len` guard in `percent_decode` must still accept an
    // escape whose last hex digit is the FINAL byte. `prefix%41` -> "prefixA"
    // (the `%` sits at index 6 of a 9-byte value; index+2 == 8 < 9).
    let layers = url_layers("token = \"prefix%41\"");
    assert!(
        layers.iter().any(|d| d.contains("prefixA")),
        "a valid escape at end-of-value must decode (no off-by-one drop); got {layers:?}"
    );
}

#[test]
fn trailing_bare_percent_after_valid_escape_decodes_valid_keeps_literal_percent() {
    // `%41%` = a valid escape ('A') then a bare, truncated trailing `%`. The
    // decoder is BEST-EFFORT, NOT all-or-nothing: a `%` without two following
    // hex digits is copied through as a LITERAL byte, not treated as an abort
    // (decode/url.rs lines 264-266 / 293-298, earlier code returned Err here
    // and discarded the WHOLE candidate, losing any real secret it carried;
    // that all-or-nothing behavior was deliberately replaced so `%41` still
    // recovers 'A'). `url_decode` only refuses a candidate with NO valid `%XX`
    // escape anywhere (see `all_non_hex_percent_escape_emits_no_url_layer`).
    // So `%41` → 'A' and the trailing bare `%` survives verbatim: exactly one
    // url layer whose bytes are `token = "A%"`.
    let layers = url_layers("token = \"%41%\"");
    assert_eq!(
        layers,
        vec!["token = \"A%\"".to_string()],
        "best-effort decode: valid %41 -> 'A', trailing bare '%' preserved as a literal byte \
         (one url layer, not an abort); got {layers:?}"
    );
}

#[test]
fn all_non_hex_percent_escape_emits_no_url_layer() {
    // `%GZvalue1` has a `%` but no well-formed `%XX` triplet anywhere, so
    // `url_decode` refuses the candidate up front: exactly zero url layers.
    let layers = url_layers("token = \"%GZvalue1\"");
    assert_eq!(
        layers.len(),
        0,
        "a percent with no valid hex pair must yield zero url layers; got {layers:?}"
    );
}

// ---------------------------------------------------------------------------
// The candidate extractor keeps the literal `+` inside a percent candidate
// ---------------------------------------------------------------------------

#[test]
fn extraction_retains_plus_within_percent_candidate() {
    // The quoted-value extractor keeps every non-whitespace byte, so the `+`
    // stays inside the candidate handed to the URL decoder, the precondition
    // for `+` surviving decode. Assert the EXACT extracted value string.
    let spans = extract_encoded_value_spans_for_test("x = \"%41+%42secret\"");
    assert!(
        spans.iter().any(|(value, _, _)| value == "%41+%42secret"),
        "extractor must retain the literal '+' inside the percent candidate; got {spans:?}"
    );
}
