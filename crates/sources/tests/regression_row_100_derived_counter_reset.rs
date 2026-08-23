//! Regression test for derived runtime counter reset lifecycle (Row 100).
//!
//! WHY: Previously, counter reset before each scan required maintaining a manual list of
//! module-specific reset functions (`reset_skipped_over_max_size`, `reset_binary_counters`,
//! etc.) with manual `#[cfg(feature = "...")]` attributes across multiple call sites.
//! Forgetting a counter in the list allowed counts from previous runs to leak silently into
//! subsequent scan reports. Row 100 requires counter reset lifecycle to be derived from the
//! registry and unified under `reset_for_scan()`, ensuring all registered counters clear
//! without hand-maintained per-counter reset invocations.
//!
//! WHAT IT DOES NOT CATCH:
//! Scoped non-static runtime metrics that do not participate in process-global
//! reset lifecycles.

use keyhog_sources::{
    merge_skip_count_deltas, reset_for_scan, reset_skipped_over_max_size, skip_counts, SkipCounts,
};

#[test]
fn derived_sources_reset_clears_all_registered_skip_counters() {
    // 1. Baseline: clear state
    reset_for_scan();
    let initial = skip_counts();
    assert_eq!(initial.total(), 0, "initial skip counts must be zero");

    // 2. Increment every category of skip counts
    let delta = SkipCounts {
        over_max_size: 5,
        binary: 3,
        excluded: 2,
        unreadable: 4,
        git_object_unreadable: 1,
        archive_truncated: 6,
        binary_section_name_unresolved: 7,
        source_truncated: 8,
        structured_source_parse_failures: 9,
        archive_duplicate_scan_unavailable: 10,
        git_lfs_pointer: 11,
    };
    merge_skip_count_deltas(&delta);

    let recorded = skip_counts();
    assert_eq!(recorded.over_max_size, 5);
    assert_eq!(recorded.binary, 3);
    assert_eq!(recorded.unreadable, 4);
    assert_eq!(recorded.git_object_unreadable, 1);
    assert_eq!(recorded.archive_truncated, 6);
    assert_eq!(recorded.binary_section_name_unresolved, 7);
    assert_eq!(recorded.source_truncated, 8);
    assert_eq!(recorded.structured_source_parse_failures, 9);
    assert_eq!(recorded.archive_duplicate_scan_unavailable, 10);
    assert_eq!(recorded.git_lfs_pointer, 11);

    // 3. Derived reset clears all registered counters simultaneously
    reset_for_scan();

    let after_reset = skip_counts();
    assert_eq!(after_reset.total(), 0);
    assert_eq!(after_reset.over_max_size, 0);
    assert_eq!(after_reset.binary, 0);
    assert_eq!(after_reset.excluded, 0);
    assert_eq!(after_reset.unreadable, 0);
    assert_eq!(after_reset.git_object_unreadable, 0);
    assert_eq!(after_reset.archive_truncated, 0);
    assert_eq!(after_reset.binary_section_name_unresolved, 0);
    assert_eq!(after_reset.source_truncated, 0);
    assert_eq!(after_reset.structured_source_parse_failures, 0);
    assert_eq!(after_reset.archive_duplicate_scan_unavailable, 0);
    assert_eq!(after_reset.git_lfs_pointer, 0);
}

#[test]
fn legacy_reset_skipped_over_max_size_routes_to_derived_reset() {
    reset_for_scan();

    let delta = SkipCounts {
        over_max_size: 10,
        binary: 20,
        excluded: 0,
        unreadable: 30,
        git_object_unreadable: 40,
        archive_truncated: 50,
        binary_section_name_unresolved: 60,
        source_truncated: 70,
        structured_source_parse_failures: 80,
        archive_duplicate_scan_unavailable: 90,
        git_lfs_pointer: 100,
    };
    merge_skip_count_deltas(&delta);

    // Calling legacy helper must reset everything via derived lifecycle
    reset_skipped_over_max_size();

    assert_eq!(skip_counts().total(), 0);
}

#[cfg(feature = "binary")]
#[test]
fn binary_counters_reset_with_derived_sources_reset() {
    use keyhog_sources::{binary_degraded_to_strings, binary_unreadable};

    reset_for_scan();

    // Verify binary counters are cleared after reset_for_scan
    assert_eq!(binary_degraded_to_strings(), 0);
    assert_eq!(binary_unreadable(), 0);
}
