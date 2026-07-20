//! C-style octal escapes accept one to three octal digits and stop before the
//! first non-octal byte.

use keyhog_scanner::testing::octal_escape_decode_for_test;

#[test]
fn octal_escape_accepts_one_digit() {
    let decoded = octal_escape_decode_for_test(r"prefix\0suffix")
        .expect("single-digit C octal escape must decode");
    assert_eq!(decoded.as_bytes(), b"prefix\0suffix");
}

#[test]
fn octal_escape_accepts_two_digits_at_eol() {
    let decoded =
        octal_escape_decode_for_test(r"secret=\07").expect("two-digit C octal escape must decode");
    assert_eq!(decoded.as_bytes(), b"secret=\x07");
}

#[test]
fn octal_escape_stops_before_non_octal_digits() {
    let decoded = octal_escape_decode_for_test(r"value=\089")
        .expect("valid octal prefix must decode before non-octal digits");
    assert_eq!(decoded.as_bytes(), b"value=\089");
}
