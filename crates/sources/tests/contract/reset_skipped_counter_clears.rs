//! reset_skipped_over_max_size must zero the global skip counter.

use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{reset_skipped_over_max_size, skip_counts};

#[test]
fn reset_skipped_counter_clears() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.bump_skipped_over_max_size(3);
    reset_skipped_over_max_size();
    assert_eq!(skip_counts().over_max_size, 0);
}
