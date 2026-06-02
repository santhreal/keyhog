//! take_hex_digits must reject empty iterator without panic.

use keyhog_scanner::testing::take_hex_digits;

#[test]
fn take_hex_digits_empty_iterator() {
    let mut it = "".chars().peekable();
    let result = take_hex_digits(&mut it, 1);
    assert!(
        result.is_err(),
        "take_hex_digits on empty iterator must return Err, got {:?}",
        result
    );
}

#[test]
fn take_hex_digits_exhausted_before_count() {
    let mut it = "a".chars().peekable();
    let result = take_hex_digits(&mut it, 4);
    assert!(
        result.is_err(),
        "take_hex_digits requesting 4 digits from 1-char input must error"
    );
}

#[test]
fn take_hex_digits_zero_count_returns_zero() {
    let mut it = "deadbeef".chars().peekable();
    // Requesting 0 hex digits should succeed and return 0x0.
    let result = take_hex_digits(&mut it, 0);
    assert_eq!(result, Ok(0), "zero-digit request must yield 0x0");
    // Iterator must not advance.
    assert_eq!(it.next(), Some('d'), "iterator must not be consumed");
}
