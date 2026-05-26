//! Shannon entropy stays within [0, 8] bits per byte for all inputs.

use keyhog_scanner::entropy::shannon_entropy;
use proptest::prelude::*;

#[test]
fn shannon_entropy_bounded_zero_to_eight() {
    proptest!(|(data: Vec<u8>)| {
        let e = shannon_entropy(&data);
        prop_assert!(e >= 0.0 && e <= 8.0, "entropy out of range: {e} for len {}", data.len());
    });
}
