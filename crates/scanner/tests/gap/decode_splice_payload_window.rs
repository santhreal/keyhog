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

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one example each; these SWEEP them. `bytecount_newlines`
// (memchr SIMD) must EXACTLY equal the naive `\n` count for any bytes, a
// DIFFERENTIAL that keeps the SIMD path behavior-identical to the old scalar loop.
// `splice_decoded_payload_at` gets a raw-decoder splice round-trip in a small
// parent (window covers it, so decoded replaces the span with context preserved)
// and out-of-bounds rejection. Traced against the two functions. No proptest before.

use proptest::prelude::*;

fn naive_newlines(data: &[u8]) -> usize {
    data.iter().filter(|&&b| b == b'\n').count()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// SIMD newline count equals the naive count over arbitrary bytes.
    #[test]
    fn newline_count_matches_naive_arbitrary(data in prop::collection::vec(any::<u8>(), 0..128)) {
        prop_assert_eq!(count_newlines(&data), naive_newlines(&data));
    }

    /// The same differential over a newline-rich alphabet.
    #[test]
    fn newline_count_matches_naive_rich(idxs in prop::collection::vec(0usize..3, 0..60)) {
        let data: Vec<u8> = idxs.iter().map(|&i| [b'a', b'\n', b'b'][i]).collect();
        prop_assert_eq!(count_newlines(&data), naive_newlines(&data));
    }

    /// A raw-decoder splice in a small parent (fully inside the context window)
    /// replaces `[start, end)` with the decoded text, preserving both sides, the
    /// window starts at 0 and the decoded sits at `start`.
    #[test]
    fn raw_splice_replaces_span_in_small_parent(
        prefix in "[a-zA-Z0-9]{0,8}",
        mid in "[a-zA-Z0-9]{1,8}",
        suffix in "[a-zA-Z0-9]{0,8}",
        decoded in "[a-zA-Z0-9]{1,10}",
    ) {
        let parent = format!("{prefix}{mid}{suffix}");
        let start = prefix.len();
        let end = start + mid.len();
        let expected = format!("{prefix}{decoded}{suffix}");
        let got = splice_at(&parent, start, end, &decoded, "raw");
        prop_assert_eq!(got, Some((0, expected, start)));
    }

    /// An out-of-bounds span (end past the parent, or start > end) is rejected with
    /// `None`, never a panic.
    #[test]
    fn out_of_bounds_span_yields_none_sweep(
        parent in "[a-zA-Z0-9]{0,20}",
        decoded in "[a-zA-Z0-9]{1,8}",
    ) {
        prop_assert!(splice_at(&parent, 0, parent.len() + 1, &decoded, "raw").is_none());
        prop_assert!(splice_at(&parent, parent.len() + 2, parent.len() + 1, &decoded, "raw").is_none());
    }
}
