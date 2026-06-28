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
