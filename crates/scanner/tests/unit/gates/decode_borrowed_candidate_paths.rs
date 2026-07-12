//! Gate whole-chunk decoders against clone-collecting borrowed candidates.

fn impl_body<'a>(src: &'a str, marker: &str, end_marker: &str) -> &'a str {
    src.split(marker)
        .nth(1)
        .and_then(|tail| tail.split(end_marker).next())
        .expect("requested decoder body is extractable")
}

#[test]
fn hot_decoders_decode_borrowed_candidates_without_clone_collect() {
    let pipeline = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/decode/pipeline/splice.rs"
    ))
    .expect("decode pipeline splice source readable");
    assert!(
        pipeline.contains("fn decode_candidate_refs_exact<'a, I, F>"),
        "decode pipeline must expose a borrowed Exact-splice candidate helper"
    );

    let base64 =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/decode/base64.rs"))
            .expect("base64 source readable");
    let base64_body = impl_body(
        &base64,
        "impl Decoder for Base64Decoder",
        "pub(super) struct Z85Decoder",
    );
    assert!(
        base64_body.contains("visit_classified_base64_string_spans(&chunk.data, 12")
            && !base64_body.contains("find_classified_base64_string_spans"),
        "base64 decoder should visit borrowed classified candidates directly"
    );
    let z85_body = impl_body(
        &base64,
        "impl Decoder for Z85Decoder",
        "#[derive(Clone, Copy)]",
    );
    assert!(
        z85_body.contains("visit_z85_string_spans(&chunk.data, 20")
            && !z85_body.contains("find_z85_string_spans"),
        "Z85 decoder should visit borrowed candidates and allocate only when whitespace cleaning is needed"
    );

    let hex = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/decode/hex.rs"))
        .expect("hex source readable");
    let hex_body = impl_body(
        &hex,
        "impl Decoder for HexDecoder",
        "pub fn find_hex_strings",
    );
    assert!(
        hex_body.contains("decode_candidate_refs_exact(")
            && !hex_body.contains("find_hex_string_spans(&chunk.data"),
        "hex decoder should decode borrowed candidate refs instead of clone-collecting spans"
    );

    let reverse = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/decode/reverse.rs"
    ))
    .expect("reverse source readable");
    let reverse_body = impl_body(
        &reverse,
        "impl Decoder for ReverseDecoder",
        "pub(crate) fn reverse_str",
    );
    assert!(
        reverse_body.contains("decode_candidate_refs_exact(")
            && !reverse_body.contains(".cloned()")
            && !reverse_body.contains(".collect()"),
        "reverse decoder should stream borrowed candidates into decode"
    );
    let looks_reversible_body = impl_body(
        &reverse,
        "pub(crate) fn looks_reversible",
        "REVERSED_PREFIX_AC",
    );
    assert!(
        !looks_reversible_body.contains("reverse_str(candidate)"),
        "reverse prefilter should search reversed known prefixes without allocating a reversed candidate"
    );

    let url = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/decode/url.rs"))
        .expect("url source readable");
    assert!(
        !url.contains("HexEscapeDecoder")
            && !url.contains("hex_escape_decode")
            && !url.contains("\"hex-escape\""),
        "`\\xNN` escape decoding must stay owned by UnicodeEscapeDecoder, not a duplicate hex-escape decoder"
    );
    let url_body = impl_body(
        &url,
        "impl Decoder for UrlDecoder",
        "impl Decoder for QuotedPrintableDecoder",
    );
    assert!(
        url_body.contains("if !chunk.data.contains('%')")
            && url_body.contains("decode_candidate_refs_exact(")
            && url_body.contains("percent_assignment_tail_candidates(")
            && !url_body.contains(".cloned()")
            && !url_body.contains(".collect::<Vec<_>>()"),
        "URL decoder should skip no-percent chunks before extraction, stream shared percent candidates, and own only synthetic assignment tails"
    );
    let qp_body = impl_body(
        &url,
        "impl Decoder for QuotedPrintableDecoder",
        "/// True if `s` contains",
    );
    assert!(
        qp_body.contains("with_extracted_value_spans(&chunk.data")
            && qp_body.contains("decode_candidate_refs_exact(")
            && !qp_body.contains("extract_encoded_values(")
            && !qp_body.contains("decode_candidates("),
        "quoted-printable decoder should reuse the whole-chunk candidate view instead of re-extracting per line"
    );
    let mime_body = impl_body(
        &url,
        "impl Decoder for MimeEncodedWordDecoder",
        "fn percent_decode",
    );
    assert!(
        mime_body.contains("decode_candidate_spans_exact(")
            && mime_body.contains("find_mime_encoded_word_spans(&chunk.data)")
            && !mime_body.contains("decode_candidates("),
        "MIME encoded-word decoder should preserve parser spans instead of using synthetic decode candidates"
    );
    let macro_body = impl_body(&url, "macro_rules! simple_decoder", "simple_decoder!(");
    assert!(
        macro_body.contains("decode_candidate_refs_exact(")
            && !macro_body.contains(".cloned()")
            && !macro_body.contains(".collect::<Vec<_>>()"),
        "simple escape/entity decoders should stream borrowed candidates"
    );

    for (name, marker, end_marker) in [
        (
            "html named entity",
            "fn html_named_entity_decode",
            "fn html_numeric_entity_decode",
        ),
        (
            "html numeric entity",
            "fn html_numeric_entity_decode",
            "fn octal_escape_decode",
        ),
        (
            "octal escape",
            "fn octal_escape_decode",
            "fn contains_octal_escape",
        ),
    ] {
        let body = impl_body(&url, marker, end_marker);
        assert!(
            body.contains("Option<String>")
                && !body.contains("let mut decoded = String::with_capacity(input.len())"),
            "{name} decoder should allocate output lazily after a real output-changing escape"
        );
    }

    let unicode = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/decode/unicode_escape.rs"
    ))
    .expect("unicode escape source readable");
    let unicode_body = impl_body(&unicode, "pub(super) fn unicode_escape_decode", "fn ");
    assert!(
        unicode_body.contains("let mut decoded_text: Option<String> = None")
            && !unicode_body.contains("let mut decoded_text = String::with_capacity(input.len())"),
        "unicode escape decoder should allocate output lazily after a real escape"
    );

    let registry = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/decode/pipeline/registry.rs"
    ))
    .expect("decoder registry source readable");
    assert!(
        registry.contains("Arc::new(UnicodeEscapeDecoder)")
            && !registry.contains("Arc::new(HexEscapeDecoder)"),
        "decoder registry must not run a duplicate hex-escape pass for `\\xNN` inputs"
    );
}
