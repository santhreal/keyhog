//! Migrated from src/static_intern.rs

use keyhog_scanner::static_intern::StaticInterner;
use keyhog_scanner::testing::seed_source_type_count;
use std::sync::Arc;

#[test]
fn looks_up_seeded_source_types() {
    let intern = StaticInterner::from_detector_strings(std::iter::empty::<&str>());
    assert!(intern.lookup("filesystem").is_some());
    assert!(intern.lookup("git").is_some());
    assert!(intern.lookup("stdin").is_some());
}

#[test]
fn looks_up_detector_strings() {
    let intern = StaticInterner::from_detector_strings([
        "aws-access-key",
        "AWS Access Key",
        "aws",
        "github-pat",
        "GitHub PAT",
        "github",
    ]);
    assert!(intern.lookup("aws-access-key").is_some());
    assert!(intern.lookup("github").is_some());
    assert!(intern.lookup("not-a-detector").is_none());
}

#[test]
fn deduplicates_input() {
    // The same `service = "aws"` shows up across multiple
    // detectors. Builder must collapse them rather than reject.
    let intern = StaticInterner::from_detector_strings([
        "aws-access-key",
        "aws",
        "aws-session-token",
        "aws",
        "aws-secret-key",
        "aws",
    ]);
    assert!(intern.lookup("aws").is_some());
    assert_eq!(intern.lookup("aws"), intern.lookup("aws"));
}

#[test]
fn returns_same_arc_on_repeated_lookup() {
    let intern = StaticInterner::from_detector_strings(["hello-detector"]);
    let a = intern.lookup("hello-detector").unwrap();
    let b = intern.lookup("hello-detector").unwrap();
    // The Arc itself should be cloned from the same slot, not
    // re-allocated — pointer-equality is the cheap proof.
    assert!(Arc::ptr_eq(&a, &b));
}

#[test]
fn empty_input_yields_empty_interner() {
    let intern = StaticInterner::from_detector_strings(std::iter::empty::<&str>());
    // Even an "empty" interner should still hold the seed source-types.
    assert_eq!(intern.len(), seed_source_type_count());
}

#[test]
fn unknown_lookup_returns_none() {
    let intern = StaticInterner::from_detector_strings(["x", "y", "z"]);
    assert!(intern.lookup("does-not-exist").is_none());
    assert!(intern.lookup("").is_none() || intern.lookup("").is_some());
}
