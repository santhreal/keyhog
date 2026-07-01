//! Pure tests for the structured (SARIF/HTML) coverage-gap summary.
//!
//! `coverage_gap_summary` is a pure function of a [`CoverageCounts`] snapshot,
//! so every category can be exercised directly here without touching the
//! process-global counters. The contract these lock: the structured surface
//! reports EVERY coverage-gap category (a category the human end-of-scan summary
//! can print but the structured report omits is a false-clean, Law 10). Two
//! categories previously drifted out of the structured path — unreadable
//! *binaries* and the structured decode-through oversize skip — and are
//! regression-locked below.

use super::{coverage_gap_summary, CoverageCounts};
use keyhog_sources::SkipCounts;

/// Look up the count reported for the first category whose reason contains
/// `needle`, or `None` if that category was filtered out (count zero).
fn count_for(summary: &[(String, usize)], needle: &str) -> Option<usize> {
    summary
        .iter()
        .find(|(reason, _)| reason.contains(needle))
        .map(|(_, count)| *count)
}

fn with_skip(skip: SkipCounts) -> CoverageCounts {
    CoverageCounts {
        skip,
        ..Default::default()
    }
}

// ── empty / filtering ────────────────────────────────────────────────────────

#[test]
fn empty_snapshot_yields_no_entries() {
    let summary = coverage_gap_summary(&CoverageCounts::default());
    assert!(
        summary.is_empty(),
        "a scan with zero coverage gaps must produce no notifications, got {summary:?}"
    );
}

#[test]
fn zero_count_categories_are_filtered_out() {
    let counts = with_skip(SkipCounts {
        over_max_size: 4,
        ..Default::default()
    });
    let summary = coverage_gap_summary(&counts);
    assert_eq!(
        summary.len(),
        1,
        "only the single non-zero category may appear, got {summary:?}"
    );
    assert_eq!(count_for(&summary, "exceeded --max-file-size"), Some(4));
}

// ── source-walker categories ─────────────────────────────────────────────────

#[test]
fn over_max_size_surfaces() {
    let s = coverage_gap_summary(&with_skip(SkipCounts {
        over_max_size: 7,
        ..Default::default()
    }));
    assert_eq!(count_for(&s, "exceeded --max-file-size"), Some(7));
}

#[test]
fn binary_surfaces() {
    let s = coverage_gap_summary(&with_skip(SkipCounts {
        binary: 3,
        ..Default::default()
    }));
    assert_eq!(
        count_for(&s, "binary (extension or content sniff)"),
        Some(3)
    );
}

#[test]
fn excluded_surfaces() {
    let s = coverage_gap_summary(&with_skip(SkipCounts {
        excluded: 9,
        ..Default::default()
    }));
    assert_eq!(count_for(&s, "default-exclusion list"), Some(9));
}

#[test]
fn unreadable_surfaces() {
    let s = coverage_gap_summary(&with_skip(SkipCounts {
        unreadable: 5,
        ..Default::default()
    }));
    assert_eq!(
        count_for(&s, "unreadable (permission denied or I/O error)"),
        Some(5)
    );
}

#[test]
fn git_object_unreadable_surfaces() {
    let s = coverage_gap_summary(&with_skip(SkipCounts {
        git_object_unreadable: 2,
        ..Default::default()
    }));
    assert_eq!(count_for(&s, "Git object unreadable"), Some(2));
}

#[test]
fn archive_truncated_surfaces() {
    let s = coverage_gap_summary(&with_skip(SkipCounts {
        archive_truncated: 6,
        ..Default::default()
    }));
    assert_eq!(count_for(&s, "archive extraction truncated"), Some(6));
}

#[test]
fn binary_section_name_unresolved_surfaces() {
    let s = coverage_gap_summary(&with_skip(SkipCounts {
        binary_section_name_unresolved: 1,
        ..Default::default()
    }));
    assert_eq!(count_for(&s, "binary section name unresolved"), Some(1));
}

#[test]
fn source_truncated_surfaces() {
    let s = coverage_gap_summary(&with_skip(SkipCounts {
        source_truncated: 8,
        ..Default::default()
    }));
    assert_eq!(count_for(&s, "source scan truncated by aggregate"), Some(8));
}

#[test]
fn structured_source_parse_failures_surfaces() {
    let s = coverage_gap_summary(&with_skip(SkipCounts {
        structured_source_parse_failures: 4,
        ..Default::default()
    }));
    assert_eq!(count_for(&s, "structured source parse failed"), Some(4));
}

#[test]
fn archive_duplicate_scan_unavailable_surfaces() {
    let s = coverage_gap_summary(&with_skip(SkipCounts {
        archive_duplicate_scan_unavailable: 3,
        ..Default::default()
    }));
    assert_eq!(count_for(&s, "archive duplicate-entry detection"), Some(3));
}

#[test]
fn git_lfs_pointer_surfaces() {
    let s = coverage_gap_summary(&with_skip(SkipCounts {
        git_lfs_pointer: 2,
        ..Default::default()
    }));
    assert_eq!(count_for(&s, "Git-LFS pointer"), Some(2));
}

// ── source errors + scanner telemetry ────────────────────────────────────────

#[test]
fn source_errors_surface() {
    let s = coverage_gap_summary(&CoverageCounts {
        source_errors: 5,
        ..Default::default()
    });
    assert_eq!(count_for(&s, "source emitted error rows"), Some(5));
}

#[test]
fn scanner_structured_parse_failures_surface() {
    let s = coverage_gap_summary(&CoverageCounts {
        scanner_structured_parse_failures: 3,
        ..Default::default()
    });
    assert_eq!(count_for(&s, "scanner structured parse failed"), Some(3));
}

/// Regression: the structured decode-through oversize skip was surfaced by the
/// human summary but omitted from the structured (SARIF/HTML) report.
#[test]
fn scanner_structured_oversize_skip_surfaces() {
    let s = coverage_gap_summary(&CoverageCounts {
        scanner_structured_oversize_skips: 4,
        ..Default::default()
    });
    assert_eq!(
        count_for(&s, "scanner structured decode-through skipped by size cap"),
        Some(4),
        "structured decode-through oversize skips must reach the structured report"
    );
}

#[test]
fn scanner_decode_truncations_surface() {
    let s = coverage_gap_summary(&CoverageCounts {
        scanner_decode_truncations: 6,
        ..Default::default()
    });
    assert_eq!(count_for(&s, "scanner decode-through truncated"), Some(6));
}

#[test]
fn scanner_invalid_pattern_index_skips_surface() {
    let s = coverage_gap_summary(&CoverageCounts {
        scanner_invalid_pattern_index_skips: 2,
        ..Default::default()
    });
    assert_eq!(
        count_for(
            &s,
            "scanner pattern expansion skipped by invalid pattern index"
        ),
        Some(2)
    );
}

#[test]
fn scanner_boundary_cardinality_mismatches_surface() {
    let s = coverage_gap_summary(&CoverageCounts {
        scanner_boundary_cardinality_mismatches: 1,
        ..Default::default()
    });
    assert_eq!(
        count_for(&s, "scanner boundary reassembly skipped"),
        Some(1)
    );
}

#[test]
fn scanner_line_offset_mismatches_surface() {
    let s = coverage_gap_summary(&CoverageCounts {
        scanner_line_offset_mismatches: 3,
        ..Default::default()
    });
    assert_eq!(
        count_for(
            &s,
            "scanner multiline attribution used fallback source offsets"
        ),
        Some(3)
    );
}

// ── binary-source categories (the drift bug) ─────────────────────────────────

#[test]
fn binary_degraded_surfaces() {
    let s = coverage_gap_summary(&CoverageCounts {
        binary_degraded: 2,
        ..Default::default()
    });
    assert_eq!(
        count_for(&s, "binary deep analysis degraded to strings-only"),
        Some(2)
    );
}

/// Regression: unreadable *binaries* were surfaced by the human summary but
/// omitted from the structured (SARIF/HTML) report — a structured false-clean.
#[test]
fn binary_unreadable_surfaces() {
    let s = coverage_gap_summary(&CoverageCounts {
        binary_unreadable: 4,
        skip: SkipCounts {
            unreadable: 4,
            ..Default::default()
        },
        ..Default::default()
    });
    assert_eq!(
        count_for(
            &s,
            "binary unreadable (permission denied or I/O error; binary NOT scanned)"
        ),
        Some(4),
        "unreadable binaries must reach the structured report, not just the human summary"
    );
}

// ── double-count guard ───────────────────────────────────────────────────────

#[test]
fn unreadable_count_excludes_unreadable_binaries() {
    // The `unreadable` file-walk counter includes binaries dropped as unreadable.
    // Since those are reported as their own `binary unreadable` category, the
    // generic `unreadable` line must subtract them so the same file is not
    // double-counted across two notifications.
    let s = coverage_gap_summary(&CoverageCounts {
        binary_unreadable: 2,
        skip: SkipCounts {
            unreadable: 5,
            ..Default::default()
        },
        ..Default::default()
    });
    assert_eq!(
        count_for(&s, "unreadable (permission denied or I/O error)"),
        Some(3),
        "generic unreadable must exclude the 2 unreadable binaries (5 - 2 = 3)"
    );
    assert_eq!(
        count_for(&s, "binary unreadable (permission denied"),
        Some(2)
    );
}

#[test]
fn all_unreadable_being_binaries_drops_the_generic_line() {
    // When every unreadable file is a binary, the generic unreadable count is 0
    // and its line is filtered out, but the binary category still reports them.
    let s = coverage_gap_summary(&CoverageCounts {
        binary_unreadable: 3,
        skip: SkipCounts {
            unreadable: 3,
            ..Default::default()
        },
        ..Default::default()
    });
    assert_eq!(
        count_for(&s, "unreadable (permission denied or I/O error)"),
        None,
        "no non-binary unreadable files remain, so the generic line must be filtered out"
    );
    assert_eq!(
        count_for(&s, "binary unreadable (permission denied"),
        Some(3)
    );
}

// ── structural contracts ─────────────────────────────────────────────────────

/// Set EVERY counter and assert the summary is well-formed: one entry per
/// category, all reasons unique and non-empty. This is the drift guard — if a
/// new counter is added without a distinct reason it trips here.
fn all_ones() -> CoverageCounts {
    CoverageCounts {
        skip: SkipCounts {
            over_max_size: 1,
            binary: 1,
            excluded: 1,
            unreadable: 2, // 2 so 1 remains after subtracting binary_unreadable
            git_object_unreadable: 1,
            archive_truncated: 1,
            binary_section_name_unresolved: 1,
            source_truncated: 1,
            structured_source_parse_failures: 1,
            archive_duplicate_scan_unavailable: 1,
            git_lfs_pointer: 1,
        },
        source_errors: 1,
        scanner_structured_parse_failures: 1,
        scanner_structured_oversize_skips: 1,
        scanner_decode_truncations: 1,
        scanner_invalid_pattern_index_skips: 1,
        scanner_boundary_cardinality_mismatches: 1,
        scanner_line_offset_mismatches: 1,
        binary_degraded: 1,
        binary_unreadable: 1,
    }
}

#[test]
fn every_category_surfaces_when_all_counters_are_nonzero() {
    let s = coverage_gap_summary(&all_ones());
    // 11 skip fields + source_errors + 6 scanner telemetry + 2 binary = 20.
    assert_eq!(
        s.len(),
        20,
        "every one of the 20 coverage-gap categories must surface, got {} ({s:?})",
        s.len()
    );
}

#[test]
fn all_reasons_are_unique() {
    let s = coverage_gap_summary(&all_ones());
    let mut reasons: Vec<&str> = s.iter().map(|(r, _)| r.as_str()).collect();
    reasons.sort_unstable();
    let unique = {
        let mut u = reasons.clone();
        u.dedup();
        u.len()
    };
    assert_eq!(
        unique,
        reasons.len(),
        "two categories share a reason string (a drift/copy bug): {reasons:?}"
    );
}

#[test]
fn all_reasons_are_nonempty() {
    let s = coverage_gap_summary(&all_ones());
    assert!(
        s.iter().all(|(r, _)| !r.trim().is_empty()),
        "every coverage-gap reason must be a non-empty sentence"
    );
}

#[test]
fn surfaced_count_equals_input_count() {
    let s = coverage_gap_summary(&with_skip(SkipCounts {
        over_max_size: 42,
        ..Default::default()
    }));
    assert_eq!(
        count_for(&s, "exceeded --max-file-size"),
        Some(42),
        "the surfaced count must be the exact input count, not a boolean/clamp"
    );
}
