//! Migrated from `src/lib.rs` inline tests.

use keyhog_core::{embedded_detector_count, embedded_detector_tomls};

#[test]
fn embedded_detector_count_matches_slice_len() {
    assert_eq!(embedded_detector_count(), embedded_detector_tomls().len());
    assert!(embedded_detector_count() > 0, "embedded detector catalog must be non-empty");
}
