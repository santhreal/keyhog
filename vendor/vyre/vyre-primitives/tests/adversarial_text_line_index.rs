//! Adversarial oracle tests for `text::line_index`.

use vyre_primitives::text::line_index::reference_line_index;

#[test]
fn line_index_hostile_corpus() {
    let cases: &[(&[u8], &[u32])] = &[
        (b"", &[]),
        (b"a", &[0]),
        (b"a\nb", &[0, 0, 1]),
        (b"a\r\nb", &[0, 0, 0, 1]),
        (b"\r\n\r\n", &[0, 0, 1, 1]),
    ];
    for (idx, (source, expected)) in cases.iter().enumerate() {
        assert_eq!(
            reference_line_index(source),
            *expected,
            "Fix: line_index oracle mismatch on case {idx}"
        );
    }
}
