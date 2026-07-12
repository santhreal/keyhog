//! Property invariants for the `src/magic.rs` byte-signature classifiers. These
//! run on every scanned file's leading bytes, so (1) they must NEVER panic on
//! arbitrary/truncated input, and (2) each structural gate must hold across the
//! whole input space, not just the hand-picked examples in
//! `contract/magic_byte_signatures.rs`. ~4000 cases per tier.

use keyhog_sources::testing::{
    has_bmp_header_for_test, has_bzip2_header_for_test, has_pe_header_for_test,
    has_unambiguous_binary_prefix_for_test, starts_with_pdf_for_test,
    starts_with_python_pickle_protocol2_for_test, starts_with_zip_container_prefix_for_test,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// No classifier may panic on ANY byte string (incl. empty and headers
    /// truncated mid-field) — they gate every file read, so a panic here is a
    /// scan-crashing DoS on a crafted file.
    #[test]
    fn classifiers_never_panic_on_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let _ = has_unambiguous_binary_prefix_for_test(&bytes);
        let _ = has_bmp_header_for_test(&bytes);
        let _ = has_pe_header_for_test(&bytes);
        let _ = has_bzip2_header_for_test(&bytes);
        let _ = starts_with_pdf_for_test(&bytes);
        let _ = starts_with_zip_container_prefix_for_test(&bytes);
        let _ = starts_with_python_pickle_protocol2_for_test(&bytes);
    }

    /// bzip2 is true IFF the input is exactly `BZh` followed by an ASCII digit
    /// `1..=9` (the block-size). Sweeping the 4th byte across all 256 values pins
    /// the exact digit range — `0`, `:`, letters, and control bytes all reject.
    #[test]
    fn bzip2_header_true_iff_block_size_digit_one_to_nine(
        b in any::<u8>(),
        tail in prop::collection::vec(any::<u8>(), 0..8),
    ) {
        let mut input = vec![b'B', b'Z', b'h', b];
        input.extend_from_slice(&tail);
        let expected = (b'1'..=b'9').contains(&b);
        prop_assert_eq!(has_bzip2_header_for_test(&input), expected);
    }

    /// A positive BMP result IMPLIES the `BM` prefix and >= 14 bytes — the gate
    /// can never fire without its structural precondition (no magic-less FP).
    #[test]
    fn bmp_true_implies_bm_prefix_and_min_len(
        bytes in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        if has_bmp_header_for_test(&bytes) {
            prop_assert!(bytes.starts_with(b"BM"));
            prop_assert!(bytes.len() >= 14);
        }
    }

    /// A positive PE result IMPLIES the `MZ` prefix and >= 64 bytes.
    #[test]
    fn pe_true_implies_mz_prefix_and_min_len(
        bytes in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        if has_pe_header_for_test(&bytes) {
            prop_assert!(bytes.starts_with(b"MZ"));
            prop_assert!(bytes.len() >= 64);
        }
    }

    /// Any known unambiguous binary prefix, followed by ARBITRARY bytes, always
    /// classifies as binary (the prefix match is position-0 and suffix-agnostic).
    #[test]
    fn known_binary_prefix_plus_suffix_is_always_binary(
        which in 0usize..8,
        suffix in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        const PREFIXES: &[&[u8]] = &[
            b"%PDF-",
            b"PK\x03\x04",
            b"\x89PNG\r\n\x1a\n",
            b"\x7fELF",
            b"\xff\xd8\xff",
            b"GIF89a",
            b"OggS",
            b"fLaC",
        ];
        let mut input = PREFIXES[which].to_vec();
        input.extend_from_slice(&suffix);
        prop_assert!(has_unambiguous_binary_prefix_for_test(&input));
    }
}
