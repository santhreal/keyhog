//! Regression coverage for the scanner's HTML-entity decode-through paths
//! (`crates/scanner/src/decode/url.rs`: `html_named_entity_decode` /
//! `html_numeric_entity_decode`, registered as the `html-named-entity` and
//! `html-numeric-entity` decoders).
//!
//! These decoders have no direct `*_for_test` facade, so every case drives the
//! real decode pipeline via `testing::decode_chunk` (depth 2, which admits
//! chunk-level candidate extraction) and asserts the EXACT decoded bytes of the
//! emitted layer, or the EXACT count (0) when a malformed/unknown entity must
//! not decode. Each named/numeric replacement is pinned to its concrete
//! character, and the two decoders' mutually-exclusive filters
//! (`contains('&')` vs `contains("&#")`) are verified as negative twins.
//!
//! Distinct from `regression_url_qp_html_decoders.rs`: that file spot-checks a
//! handful of entities alongside url/qp/octal/mime; this file exhaustively pins
//! the named table (`&amp;`/`&lt;`/`&gt;`/`&quot;`/`&apos;`/`&nbsp;`), the
//! numeric decimal/hex-lower/hex-upper forms, prefix preservation, malformed
//! pass-through, the semicolon requirement, surrogate/astral boundaries, and
//! the cross-decoder filter isolation.
#![cfg(feature = "decode")]

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;

/// Run the whole decode pipeline over `text` and return the `data` of every
/// emitted layer whose `source_type` names `decoder` (exactly one of
/// `"html-named-entity"` / `"html-numeric-entity"`: neither is a substring of
/// the other). Depth 2 admits the chunk-level candidate extraction.
fn layers_for(text: &str, decoder: &str) -> Vec<String> {
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    decode_chunk(&chunk, 2, false, None, None)
        .into_iter()
        .filter(|c| c.metadata.source_type.contains(decoder))
        .map(|c| c.data.as_str().to_owned())
        .collect()
}

/// True iff at least one emitted layer for `decoder` contains `needle`.
fn any_layer_contains(text: &str, decoder: &str, needle: &str) -> bool {
    layers_for(text, decoder).iter().any(|d| d.contains(needle))
}

// ---------------------------------------------------------------------------
// Named entities `&name;`: every entry in the decode table, pinned exactly
// ---------------------------------------------------------------------------

#[test]
fn named_amp_decodes_to_ampersand() {
    // `&amp;` -> `&`; the surrounding `a`/`b` copy through unchanged.
    assert!(
        any_layer_contains("k = \"a&amp;b\"", "html-named-entity", "a&b"),
        "&amp; must decode to & (a&b); got {:?}",
        layers_for("k = \"a&amp;b\"", "html-named-entity")
    );
    // Negative: the raw entity must not survive in any decoded layer.
    assert!(
        layers_for("k = \"a&amp;b\"", "html-named-entity")
            .iter()
            .all(|d| !d.contains("&amp;")),
        "decoded layer must not still contain the raw &amp; entity"
    );
}

#[test]
fn named_lt_and_gt_decode_to_angle_brackets() {
    // `&lt;` -> `<`, `&gt;` -> `>`.
    assert!(
        any_layer_contains("k = \"&lt;tag&gt;\"", "html-named-entity", "<tag>"),
        "&lt;/&gt; must decode to <tag>; got {:?}",
        layers_for("k = \"&lt;tag&gt;\"", "html-named-entity")
    );
}

#[test]
fn named_quot_decodes_to_double_quote() {
    // `&quot;` -> `"` (0x22).
    assert!(
        any_layer_contains("v = &quot;x&quot;", "html-named-entity", "\"x\""),
        "&quot; must decode to a literal double quote; got {:?}",
        layers_for("v = &quot;x&quot;", "html-named-entity")
    );
}

#[test]
fn named_apos_decodes_to_single_quote() {
    // `&apos;` -> `'` (0x27).
    assert!(
        any_layer_contains("k = \"a&apos;b\"", "html-named-entity", "a'b"),
        "&apos; must decode to a single quote (a'b); got {:?}",
        layers_for("k = \"a&apos;b\"", "html-named-entity")
    );
}

#[test]
fn named_nbsp_decodes_to_u00a0() {
    // `&nbsp;` -> U+00A0 (non-breaking space), NOT an ASCII 0x20 space.
    let layers = layers_for("k = \"x&nbsp;y\"", "html-named-entity");
    assert!(
        layers.iter().any(|d| d.contains("x\u{00A0}y")),
        "&nbsp; must decode to U+00A0; got {layers:?}"
    );
    // Negative twin: it is not a plain ASCII space.
    assert!(
        layers.iter().all(|d| !d.contains("x y")),
        "&nbsp; must not collapse to an ASCII space; got {layers:?}"
    );
}

#[test]
fn named_prefix_before_first_entity_is_preserved() {
    // lazy_decoded_prefix copies everything before the first successful decode:
    // `PREFIX&amp;TAIL` -> `PREFIX&TAIL`.
    assert!(
        any_layer_contains(
            "k = \"PREFIX&amp;TAIL\"",
            "html-named-entity",
            "PREFIX&TAIL"
        ),
        "text before the first entity must be preserved verbatim; got {:?}",
        layers_for("k = \"PREFIX&amp;TAIL\"", "html-named-entity")
    );
}

// ---------------------------------------------------------------------------
// Named entities, negative / adversarial
// ---------------------------------------------------------------------------

#[test]
fn named_unknown_entity_emits_no_named_layer() {
    // `&frac12;` is not in the decode table; with nothing else decoded the
    // decoder reports "nothing changed" and emits zero html-named-entity
    // layers (exact count 0), never a spurious pass-through layer.
    let layers = layers_for("k = \"&frac12;z\"", "html-named-entity");
    assert_eq!(
        layers.len(),
        0,
        "unknown named entity must yield zero html-named-entity layers; got {layers:?}"
    );
}

#[test]
fn named_unknown_entity_after_known_passes_through_literally() {
    // Once a real entity (`&amp;` -> `&`) has started the decoded buffer, a
    // following UNKNOWN entity is copied verbatim: `&amp;&frac12;` ->
    // `&&frac12;` (decoded amp, then literal `&frac12;`).
    assert!(
        any_layer_contains("k = \"&amp;&frac12;\"", "html-named-entity", "&&frac12;"),
        "unknown entity after a known one must pass through literally; got {:?}",
        layers_for("k = \"&amp;&frac12;\"", "html-named-entity")
    );
}

#[test]
fn named_entity_without_semicolon_does_not_decode() {
    // `&amp` (no terminating `;`, end of candidate) does not match the table,
    // so no html-named-entity layer is emitted (exact count 0).
    let layers = layers_for("k = \"&amp\"", "html-named-entity");
    assert_eq!(
        layers.len(),
        0,
        "a named entity missing its `;` must not decode; got {layers:?}"
    );
    // Negative twin: adding the `;` back DOES decode to `&`.
    assert!(
        any_layer_contains("k = \"&amp;\"", "html-named-entity", "\"&\""),
        "the same entity WITH `;` must decode to &; got {:?}",
        layers_for("k = \"&amp;\"", "html-named-entity")
    );
}

// ---------------------------------------------------------------------------
// Numeric entities `&#NN;` / `&#xNN;` / `&#XNN;`
// ---------------------------------------------------------------------------

#[test]
fn numeric_decimal_entity_decodes_to_exact_char() {
    // `&#65;` = decimal 65 = 'A'.
    let layers = layers_for("k = \"&#65;end\"", "html-numeric-entity");
    assert!(
        layers.iter().any(|d| d.contains("Aend")),
        "&#65; must decode to 'A' (Aend); got {layers:?}"
    );
    // The raw numeric entity must not survive.
    assert!(
        layers.iter().all(|d| !d.contains("&#65")),
        "decoded layer must not still contain the raw &#65 entity; got {layers:?}"
    );
}

#[test]
fn numeric_hex_entity_lowercase_x_decodes() {
    // `&#x41;` = hex 0x41 = 'A'.
    assert!(
        any_layer_contains("k = \"&#x41;end\"", "html-numeric-entity", "Aend"),
        "&#x41; must decode to 'A'; got {:?}",
        layers_for("k = \"&#x41;end\"", "html-numeric-entity")
    );
}

#[test]
fn numeric_hex_entity_uppercase_x_decodes() {
    // The decoder accepts an uppercase `X` prefix too: `&#X41;` = 'A'.
    assert!(
        any_layer_contains("k = \"&#X41;end\"", "html-numeric-entity", "Aend"),
        "&#X41; (uppercase X) must decode to 'A'; got {:?}",
        layers_for("k = \"&#X41;end\"", "html-numeric-entity")
    );
}

#[test]
fn numeric_empty_entity_emits_no_numeric_layer() {
    // `&#;` has no digits; nothing decodes (`changed` stays false) so zero
    // html-numeric-entity layers are emitted (exact count 0).
    let layers = layers_for("k = \"&#;z\"", "html-numeric-entity");
    assert_eq!(
        layers.len(),
        0,
        "digit-less numeric entity must yield zero numeric layers; got {layers:?}"
    );
}

#[test]
fn numeric_valid_then_malformed_hex_keeps_valid_and_passes_malformed() {
    // `&#65;` decodes to 'A' (sets `changed`), then `&#xZZ;` is malformed (the
    // `Z` is not a hex digit) and is copied through verbatim:
    // `&#65;&#xZZ;` -> `A&#xZZ;`.
    assert!(
        any_layer_contains("k = \"&#65;&#xZZ;\"", "html-numeric-entity", "A&#xZZ;"),
        "malformed hex after a valid entity must pass through literally; got {:?}",
        layers_for("k = \"&#65;&#xZZ;\"", "html-numeric-entity")
    );
}

#[test]
fn numeric_astral_codepoint_decodes_to_multibyte_char() {
    // Boundary: an astral-plane codepoint. `&#128512;` = U+1F600 (😀).
    let layers = layers_for("k = \"&#128512;\"", "html-numeric-entity");
    assert!(
        layers.iter().any(|d| d.contains('\u{1F600}')),
        "&#128512; must decode to U+1F600; got {layers:?}"
    );
}

#[test]
fn numeric_surrogate_codepoint_is_rejected() {
    // Adversarial boundary: `&#xD800;` is a lone UTF-16 surrogate; it is not a
    // valid Unicode scalar so `char::from_u32` fails and the decoder emits zero
    // html-numeric-entity layers (exact count 0), never an invalid layer.
    let layers = layers_for("k = \"&#xD800;\"", "html-numeric-entity");
    assert_eq!(
        layers.len(),
        0,
        "a surrogate codepoint must not decode to a layer; got {layers:?}"
    );
}

// ---------------------------------------------------------------------------
// Cross-decoder filter isolation (negative twins)
// ---------------------------------------------------------------------------

#[test]
fn numeric_only_input_emits_no_named_layer() {
    // `&#65;` contains `&` so the NAMED decoder runs its filter, but `#65;` is
    // not a table entry, so the named decoder emits nothing: zero
    // html-named-entity layers for a purely-numeric entity (exact count 0).
    let layers = layers_for("k = \"&#65;end\"", "html-named-entity");
    assert_eq!(
        layers.len(),
        0,
        "a numeric entity must not produce an html-named-entity layer; got {layers:?}"
    );
}

#[test]
fn named_only_input_emits_no_numeric_layer() {
    // `&amp;` lacks the `&#` prefix, so the numeric decoder's filter rejects it
    // and zero html-numeric-entity layers are emitted (exact count 0).
    let layers = layers_for("k = \"a&amp;b\"", "html-numeric-entity");
    assert_eq!(
        layers.len(),
        0,
        "a named entity must not produce an html-numeric-entity layer; got {layers:?}"
    );
}

// ---------------------------------------------------------------------------
// End-to-end: a secret wrapped in entities is recovered contiguously
// ---------------------------------------------------------------------------

#[test]
fn secret_behind_named_quot_entities_recovers_contiguously() {
    // A `key="value"` secret whose quotes were HTML-escaped as `&quot;` must
    // recover to the exact contiguous `password="s3cr3tV4lue"` after decode so
    // the downstream scanner sees the real assignment, not the escaped form.
    assert!(
        any_layer_contains(
            "password=&quot;s3cr3tV4lue&quot;",
            "html-named-entity",
            "password=\"s3cr3tV4lue\"",
        ),
        "entity-wrapped secret must recover to password=\"s3cr3tV4lue\"; got {:?}",
        layers_for("password=&quot;s3cr3tV4lue&quot;", "html-named-entity")
    );
}

#[test]
fn secret_behind_numeric_entities_recovers_contiguously() {
    // Each character of a token encoded as decimal entities: `&#65;&#66;&#67;`
    // = 'A''B''C'. The decoded layer must contain the contiguous run "ABC".
    assert!(
        any_layer_contains("tok = \"&#65;&#66;&#67;\"", "html-numeric-entity", "ABC"),
        "numeric-entity-encoded token must recover to ABC; got {:?}",
        layers_for("tok = \"&#65;&#66;&#67;\"", "html-numeric-entity")
    );
}
