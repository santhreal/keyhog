//! Property gates for `text::byte_histogram::reference_byte_histogram`.
//! Requires `cpu-parity` because the reference CPU oracle is gated
//! behind that feature alongside `text`.
#![cfg(all(feature = "text", feature = "cpu-parity"))]

use proptest::prelude::*;
use vyre_primitives::text::byte_histogram::reference_byte_histogram;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn histogram_sum_equals_input_length(
        bytes in proptest::collection::vec(any::<u8>(), 0..=256),
    ) {
        let hist = reference_byte_histogram(&bytes);
        let sum: u32 = hist.iter().sum();
        prop_assert_eq!(sum, bytes.len() as u32, "histogram sum must equal input length");
    }

    #[test]
    fn histogram_bins_are_nonnegative(
        bytes in proptest::collection::vec(any::<u8>(), 0..=256),
    ) {
        let hist = reference_byte_histogram(&bytes);
        for (i, &count) in hist.iter().enumerate() {
            prop_assert!(count <= bytes.len() as u32, "bin {i} exceeds input length");
        }
    }

    #[test]
    fn empty_input_yields_all_zeros(_dummy in 0u32..1) {
        let hist = reference_byte_histogram(b"");
        prop_assert_eq!(hist, [0u32; 256]);
    }

    #[test]
    fn single_byte_increments_exactly_one_bin(b in any::<u8>()) {
        let hist = reference_byte_histogram(&[b]);
        let sum: u32 = hist.iter().sum();
        prop_assert_eq!(sum, 1);
        prop_assert_eq!(hist[b as usize], 1);
    }

    #[test]
    fn histogram_is_additive_over_concatenation(
        a in proptest::collection::vec(any::<u8>(), 0..=128),
        b in proptest::collection::vec(any::<u8>(), 0..=128),
    ) {
        let mut combined = a.clone();
        combined.extend_from_slice(&b);
        let hist_a = reference_byte_histogram(&a);
        let hist_b = reference_byte_histogram(&b);
        let hist_combined = reference_byte_histogram(&combined);
        for i in 0..256 {
            prop_assert_eq!(
                hist_combined[i],
                hist_a[i].wrapping_add(hist_b[i]),
                "bin {} must be additive over concatenation",
                i
            );
        }
    }
}
