//! Property gates for `vyre_primitives::text::char_class::reference_char_class`.

#![cfg(all(feature = "text", feature = "cpu-parity"))]

use proptest::prelude::*;
use vyre_primitives::text::char_class::{build_char_class_table, reference_char_class};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn every_ascii_byte_maps_via_table(
        bytes in proptest::collection::vec(any::<u8>(), 0..=256),
    ) {
        let table = build_char_class_table();
        let result = reference_char_class(&bytes, &table);
        let expected: Vec<u32> = bytes.iter().map(|b| table[usize::from(*b)]).collect();
        prop_assert_eq!(result, expected);
    }

    #[test]
    fn table_is_deterministic(_dummy in 0u32..1) {
        let t1 = build_char_class_table();
        let t2 = build_char_class_table();
        prop_assert_eq!(t1, t2);
    }
}
