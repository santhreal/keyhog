//! Independent decode regions form combinations, not order permutations.

use keyhog_scanner::testing::canonical_decode_order_probe_for_test;

#[test]
fn independent_decode_regions_have_one_canonical_source_order() {
    let states = canonical_decode_order_probe_for_test().expect("probe policy compiles");
    assert_eq!(
        states, 385,
        "ten independent regions through depth four must produce each combination once"
    );
}
