//! Gap test: the pre-decode encoded-value extractor.
//!
//! Before any decoder runs, a single char-level pass pulls candidate encoded
//! values out of quoted strings and `key = value` / `key: value` assignments,
//! recording each value's byte span so a decoded result can be spliced back at
//! the right place. Pin the exact spans across the two extraction shapes and the
//! `MIN_EXTRACTED_VALUE_LEN` floor (now a named const = 4): a value shorter than
//! four chars is dropped, four chars or more is kept.
//!
//! The decode pipeline is portable (no feature gate), so neither is this test.

use keyhog_scanner::testing::extract_encoded_value_spans_for_test as extract;

#[test]
fn assignment_value_span_is_exact() {
    // `secretvalue` starts at byte 6 (after "key = ") and ends at 17.
    assert_eq!(
        extract("key = secretvalue"),
        vec![("secretvalue".to_string(), 6, 17)]
    );
}

#[test]
fn quoted_string_span_is_exact() {
    // The bytes inside the quotes, span [3, 14); the leading `x=` and the quote
    // itself are not part of the extracted value.
    assert_eq!(
        extract("x=\"hunter2pass\""),
        vec![("hunter2pass".to_string(), 3, 14)]
    );
}

#[test]
fn minimum_length_floor_drops_sub_four_char_values() {
    // A 3-char assignment value is below the floor and yields nothing...
    assert_eq!(extract("a = abc"), Vec::<(String, usize, usize)>::new());
    // ...but exactly four chars is kept, span [4, 8).
    assert_eq!(extract("a = abcd"), vec![("abcd".to_string(), 4, 8)]);
}

#[test]
fn freestanding_base64_run_needs_sixteen_chars() {
    // The base64 accumulator only emits a candidate at >= 16 chars: a fifteen-
    // char freestanding alphanumeric run is discarded as an ordinary word...
    assert_eq!(
        extract("abcdefghijklmno"),
        Vec::<(String, usize, usize)>::new()
    );
    // ...exactly sixteen chars is kept, span [0, 16).
    assert_eq!(
        extract("abcdefghijklmnop"),
        vec![("abcdefghijklmnop".to_string(), 0, 16)]
    );
}

#[test]
fn a_single_percent_triplet_is_kept() {
    // One `%`-triplet is the percent-run floor (MIN_PCT_TRIPLETS = 1), so `%41`
    // alone surfaces as a url-decode candidate, span [0, 3). The hex bytes are
    // NOT also accumulated as a base64 candidate.
    assert_eq!(extract("%41"), vec![("%41".to_string(), 0, 3)]);
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one example of each shape/floor; these SWEEP them. The
// KILLER is a UNIVERSAL SPAN SELF-CONSISTENCY invariant: for EVERY returned
// (value, start, end), the span must be a valid char-aligned byte range whose
// slice is EXACTLY the returned value, this is the splice-back contract, and an
// off-by-one span silently decodes into the wrong place. Then CONSTRUCTIVE recall
// for the assignment / quoted / freestanding-16 shapes and the below-floor drop.
// Traced against the extractor's documented span semantics. No proptest before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3_000))]

    /// SPLICE-BACK SAFETY: every span is a valid, char-aligned byte range within
    /// the line, and the returned value is never LONGER than its span (the value is
    /// a filtered subsequence of the raw range). Holds for arbitrary Unicode, also
    /// the no-panic guarantee.
    #[test]
    fn every_span_is_a_valid_range_bounding_its_value(line in "(?s).{0,60}") {
        for (value, start, end) in extract(&line) {
            prop_assert!(start <= end, "inverted span {}..{} in {:?}", start, end, line);
            prop_assert!(end <= line.len(), "span end {} past len in {:?}", end, line);
            prop_assert!(
                line.is_char_boundary(start) && line.is_char_boundary(end),
                "non-char-aligned span {}..{} in {:?}",
                start,
                end,
                line
            );
            prop_assert!(
                value.len() <= end - start,
                "value {:?} longer than its span {}..{} in {:?}",
                value,
                start,
                end,
                line
            );
        }
    }

    /// SPLICE-BACK CONTRACT (backslash-free input, so no escape handling): the
    /// returned value is EXACTLY the raw span with internal ASCII whitespace
    /// removed, the quoted path strips whitespace while the span covers the raw
    /// first→last non-whitespace range; all other paths carry no internal
    /// whitespace, so the strip is a no-op and value == the raw slice.
    #[test]
    fn value_is_the_whitespace_stripped_span(line in "[^\\\\]{0,60}") {
        for (value, start, end) in extract(&line) {
            let raw = &line[start..end];
            let stripped: String = raw.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            prop_assert_eq!(&value, &stripped);
        }
    }

    /// RECALL: a `key = <value>` assignment (value ≥ 4) yields the value at the
    /// byte offset right after the 4-char `"a = "` prefix.
    #[test]
    fn assignment_value_is_extracted_at_its_offset(value in "[A-Za-z0-9]{4,24}") {
        let line = format!("a = {value}");
        let len = value.len();
        prop_assert!(extract(&line).contains(&(value, 4, 4 + len)));
    }

    /// RECALL: a quoted value (≥ 4) is extracted from inside the quotes at offset 3
    /// (after the 3-char `x="` prefix).
    #[test]
    fn quoted_value_is_extracted_inside_the_quotes(value in "[A-Za-z0-9]{4,24}") {
        let line = format!("x=\"{value}\"");
        let len = value.len();
        prop_assert!(extract(&line).contains(&(value, 3, 3 + len)));
    }

    /// RECALL: a freestanding alphanumeric run of ≥ 16 chars is a base64 candidate
    /// spanning the whole run.
    #[test]
    fn freestanding_run_of_sixteen_or_more_is_a_candidate(run in "[A-Za-z0-9]{16,48}") {
        let len = run.len();
        prop_assert!(extract(&run).contains(&(run, 0, len)));
    }

    /// A freestanding run below 16 chars (no assignment / quote / percent) yields
    /// nothing (it is an ordinary word, not an encoded value).
    #[test]
    fn freestanding_run_below_sixteen_yields_nothing(run in "[A-Za-z0-9]{1,15}") {
        prop_assert!(extract(&run).is_empty());
    }
}
