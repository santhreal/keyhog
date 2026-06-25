//! Migrated from `src/lib.rs` inline tests.

use keyhog_core::embedded_detector_count;
use keyhog_core::testing::{CoreTestApi, TestApi};

#[test]
fn embedded_detector_count_matches_slice_len() {
    assert_eq!(
        embedded_detector_count(),
        CoreTestApi::embedded_detector_tomls(&TestApi).len()
    );
    assert!(
        embedded_detector_count() > 0,
        "embedded detector catalog must be non-empty"
    );
}
