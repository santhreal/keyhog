//! Normalized entropy stays within [0, 1].

use keyhog_scanner::entropy::normalized_entropy;
use proptest::prelude::*;

#[test]
fn normalized_entropy_bounded_zero_to_one() {
    proptest!(|(data: Vec<u8>)| {
        let e = normalized_entropy(&data);
        prop_assert!(e >= 0.0 && e <= 1.0 + 1e-6, "normalized entropy out of range: {e}");
    });
}
