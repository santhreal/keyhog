//! Property gates for `vyre_primitives::text::utf8_validate::reference_utf8_validate`.
#![cfg(all(feature = "text", feature = "cpu-parity"))]

use proptest::prelude::*;
use vyre_primitives::text::utf8_validate::{
    reference_utf8_validate, UTF8_ASCII, UTF8_CONT, UTF8_INVALID, UTF8_LEAD_2, UTF8_LEAD_3,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn empty_source_is_empty(_dummy in 0..1) {
        let _ = _dummy;
        prop_assert_eq!(reference_utf8_validate(&[]), Vec::<u32>::new());
    }

    #[test]
    fn all_ascii_are_class_zero(len in 0usize..64) {
        let bytes = vec![0x41u8; len];
        let expected = vec![UTF8_ASCII; len];
        prop_assert_eq!(reference_utf8_validate(&bytes), expected);
    }

    #[test]
    fn valid_two_byte_sequence(_dummy in 0..1) {
        let _ = _dummy;
        // U+00E9 (é) = 0xC3 0xA9
        prop_assert_eq!(reference_utf8_validate(&[0xC3, 0xA9]), vec![UTF8_LEAD_2, UTF8_CONT]);
    }

    #[test]
    fn valid_three_byte_sequence(_dummy in 0..1) {
        let _ = _dummy;
        // U+20AC (€) = 0xE2 0x82 0xAC
        prop_assert_eq!(reference_utf8_validate(&[0xE2, 0x82, 0xAC]), vec![UTF8_LEAD_3, UTF8_CONT, UTF8_CONT]);
    }

    #[test]
    fn standalone_continuation_byte_is_invalid(b in 0x80u8..=0xBF) {
        prop_assert_eq!(reference_utf8_validate(&[b]), vec![UTF8_INVALID]);
    }

    #[test]
    fn invalid_lead_bytes_are_invalid(b in proptest::prop_oneof![Just(0xC0), Just(0xC1), Just(0xF5), Just(0xFF)]) {
        prop_assert_eq!(reference_utf8_validate(&[b]), vec![UTF8_INVALID]);
    }

    #[test]
    fn deterministic_over_repeated_calls(bytes in proptest::collection::vec(any::<u8>(), 0..=32)) {
        let a = reference_utf8_validate(&bytes);
        let b = reference_utf8_validate(&bytes);
        prop_assert_eq!(a, b);
    }
}
