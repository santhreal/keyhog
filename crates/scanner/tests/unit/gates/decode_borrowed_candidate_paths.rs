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

    let url = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/decode/url.rs"))
        .expect("url source readable");
    let url_body = impl_body(
        &url,
        "impl Decoder for UrlDecoder",
        "impl Decoder for QuotedPrintableDecoder",
    );
    assert!(
        url_body.contains("decode_candidate_refs_exact(")
            && url_body.contains("percent_assignment_tail_candidates(")
            && !url_body.contains(".cloned()")
            && !url_body.contains(".collect::<Vec<_>>()"),
        "URL decoder should stream shared percent candidates and own only synthetic assignment tails"
    );
    let macro_body = impl_body(&url, "macro_rules! simple_decoder", "simple_decoder!(");
    assert!(
        macro_body.contains("decode_candidate_refs_exact(")
            && !macro_body.contains(".cloned()")
            && !macro_body.contains(".collect::<Vec<_>>()"),
        "simple escape/entity decoders should stream borrowed candidates"
    );
}
