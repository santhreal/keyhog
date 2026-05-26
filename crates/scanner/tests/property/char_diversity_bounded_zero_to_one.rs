//! char_diversity ratio stays within [0, 1].

use keyhog_scanner::confidence::char_diversity;
use proptest::prelude::*;

#[test]
fn char_diversity_bounded_zero_to_one() {
    proptest!(|(s: String)| {
        let d = char_diversity(&s);
        prop_assert!(d >= 0.0 && d <= 1.0, "diversity out of range: {d}");
    });
}
