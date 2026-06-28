//! Gap test: the decode pipeline's splice payload window.
//!
//! When a decoder turns an encoded blob back into plaintext, the result is
//! spliced back into the parent at the blob's position so the surrounding
//! companion anchors (`api_key =`, `Authorization:`) stay adjacent and detector
//! regexes still fire. `splice_decoded_payload_at` does that splice within a
//! bounded context window; `bytecount_newlines` (now a `memchr` SIMD count)
//! tallies the parent-prefix newlines that fix the spliced chunk's base line.
//!
//! Pin both: the exact spliced bytes (decoded text replaces `[start, end)`,
//! parent context preserved on both sides, base64 padding consumed), and the
//! exact newline count the SIMD path must keep behavior-identical to the old
//! scalar byte loop.
//!
//! The decode pipeline is portable (no feature gate), so neither is this test.

use keyhog_scanner::testing::{
    bytecount_newlines_for_test as count_newlines, splice_decoded_payload_at_for_test as splice_at,
};

#[test]
fn splice_replaces_the_span_and_keeps_parent_context() {
    // "AAAA" at [2, 6) becomes "SECRET"; the small parent fits inside the
    // context window, so the whole line is preserved with the value swapped.
    // window_start 0, decoded sits at offset 2 (right after "x=").
    assert_eq!(
        splice_at("x=AAAA;", 2, 6, "SECRET", "raw"),
        Some((0, "x=SECRET;".to_string(), 2))
    );
}

#[test]
fn base64_decoder_consumes_adjacent_padding() {
    // The `=` padding after the base64 blob is consumed (excluded from the
    // spliced output) when the decoder is base64 and a delimiter follows.
    assert_eq!(
        splice_at("k=QUJD==;", 2, 6, "DEC", "base64"),
        Some((0, "k=DEC;".to_string(), 2))
    );
}

#[test]
fn out_of_bounds_span_yields_none() {
    // An end past the parent length is rejected, not panicked on.
    assert_eq!(splice_at("abc", 1, 99, "X", "raw"), None);
}

#[test]
fn newline_count_is_exact() {
    assert_eq!(count_newlines(b"a\nb\nc"), 2);
    assert_eq!(count_newlines(b"no newlines here"), 0);
    assert_eq!(count_newlines(b""), 0);
    assert_eq!(count_newlines(b"\n\n\n"), 3);
}
