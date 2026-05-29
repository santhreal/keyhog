//! Property gates for `vyre_primitives::hash::fnv1a::fnv1a32`.

#![cfg(feature = "hash")]

use proptest::prelude::*;
use vyre_primitives::hash::fnv1a::{fnv1a32, fnv1a32_initial_state, fnv1a32_update_byte};

fn manual_fnv1a32(bytes: &[u8]) -> u32 {
    let mut h = fnv1a32_initial_state();
    for &byte in bytes {
        h = fnv1a32_update_byte(h, byte);
    }
    h
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn fnv1a32_matches_manual(bytes in proptest::collection::vec(any::<u8>(), 0..=64)) {
        prop_assert_eq!(fnv1a32(&bytes), manual_fnv1a32(&bytes));
    }

    #[test]
    fn empty_slice_is_offset_basis(_dummy in 0..1) {
        let _ = _dummy;
        prop_assert_eq!(fnv1a32(&[]), fnv1a32_initial_state());
    }

    #[test]
    fn single_byte_matches_manual(b in any::<u8>()) {
        prop_assert_eq!(fnv1a32(&[b]), manual_fnv1a32(&[b]));
    }

    #[test]
    fn concatenation_property(a in proptest::collection::vec(any::<u8>(), 0..=32), b in proptest::collection::vec(any::<u8>(), 0..=32)) {
        let mut concat = a.clone();
        concat.extend_from_slice(&b);
        let hash_concat = fnv1a32(&concat);
        let hash_a = fnv1a32(&a);
        // FNV-1a is not associative, but we can verify the incremental property:
        // hash(a || b) == continue_from(hash(a), b)
        let mut h = hash_a;
        for &byte in &b {
            h = fnv1a32_update_byte(h, byte);
        }
        prop_assert_eq!(hash_concat, h);
    }
}
