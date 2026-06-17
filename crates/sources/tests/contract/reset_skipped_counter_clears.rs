//! reset_skipped_over_max_size must zero the global skip counter.

use keyhog_sources::{
    reset_skipped_over_max_size, skip_counts, testing::bump_skipped_over_max_size,
};

#[test]
fn reset_skipped_counter_clears() {
    bump_skipped_over_max_size(3);
    reset_skipped_over_max_size();
    assert_eq!(skip_counts().over_max_size, 0);
}
