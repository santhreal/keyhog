//! Adversarial oracle tests for `text::utf8_validate` classification.

use vyre_primitives::text::utf8_validate::{
    reference_utf8_validate, UTF8_ASCII, UTF8_CONT, UTF8_INVALID, UTF8_LEAD_2, UTF8_LEAD_4,
};

#[test]
fn utf8_validate_hostile_corpus() {
    let cases: &[(&[u8], &[u32])] = &[
        (b"", &[]),
        (b"a", &[UTF8_ASCII]),
        (b"\xff", &[UTF8_INVALID]),
        (b"\xc2\x80", &[UTF8_LEAD_2, UTF8_CONT]),
        (b"\xf0\x90\x80\x80", &[UTF8_LEAD_4, UTF8_CONT, UTF8_CONT, UTF8_CONT]),
    ];
    for (idx, (source, expected)) in cases.iter().enumerate() {
        assert_eq!(
            reference_utf8_validate(source),
            *expected,
            "Fix: utf8_validate oracle mismatch on case {idx}"
        );
    }
}
