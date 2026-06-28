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
