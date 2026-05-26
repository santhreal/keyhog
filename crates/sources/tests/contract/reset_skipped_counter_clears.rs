//! reset_skipped_over_max_size must zero the global skip counter.

use keyhog_sources::{reset_skipped_over_max_size, SKIPPED_OVER_MAX_SIZE};
use std::sync::atomic::Ordering;

#[test]
fn reset_skipped_counter_clears() {
    SKIPPED_OVER_MAX_SIZE.fetch_add(3, Ordering::Relaxed);
    reset_skipped_over_max_size();
    assert_eq!(SKIPPED_OVER_MAX_SIZE.load(Ordering::Relaxed), 0);
}
