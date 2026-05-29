//! Adversarial oracle tests for `text::char_class` reference mapping.

#![allow(
    unused_imports,
    unused_variables,
    dead_code,
    unused_mut,
    clippy::identity_op
)]

use vyre_primitives::text::char_class::reference_char_class;

#[test]
fn char_class_hostile_corpus_table_driven() {
    const ZEROS: [u32; 256] = [0u32; 256];
    const MAXES: [u32; 256] = [0xffff_ffffu32; 256];
    let cases: &[(&[u8], &[u32; 256], &[u32])] = &[
        (b"", &ZEROS, &[]),
        (b"\x00", &ZEROS, &[0]),
        (b"\xff", &MAXES, &[0xffff_ffff]),
        (b"vyre", &ZEROS, &[0, 0, 0, 0]),
        (b"\x00\xff\xfe", &MAXES, &[0xffff_ffff, 0xffff_ffff, 0xffff_ffff]),
    ];
    for (idx, (source, table, expected)) in cases.iter().enumerate() {
        let got = reference_char_class(source, table);
        assert_eq!(
            got, *expected,
            "Fix: char_class oracle mismatch on hostile case {idx} (len={})",
            source.len()
        );
    }
}
