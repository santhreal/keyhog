//! Pure tests for the structured (SARIF/HTML) coverage-gap summary.
//!
//! `coverage_gap_summary` is a pure function of a [`CoverageCounts`] snapshot,
//! so every category can be exercised directly here without touching the
//! process-global counters. The contract these lock: the structured surface
//! reports EVERY coverage-gap category (a category the human end-of-scan summary
//! can print but the structured report omits is a false-clean, Law 10). Two
//! categories previously drifted out of the structured path, unreadable
//! *binaries* and the structured decode-through oversize skip, and are
//! regression-locked below.

use super::{coverage_gap_summary, CoverageCounts, CoverageGapKind, CoverageSeverity};
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
    assert_eq!(count_for(&s, "exclusion policy"), Some(9));
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
/// omitted from the structured (SARIF/HTML) report (a structured false-clean).
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
/// category, all reasons unique and non-empty. This is the drift guard, if a
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

// ── canonical CoverageGapKind contract (the human ⇄ SARIF unification) ─────────
//
// Both the human end-of-scan summary (`report_skip_summary`) and the SARIF
// report (`coverage_gap_summary`) iterate the SAME `CoverageGapKind::ALL`. These
// lock the single-source contract so the two surfaces can never drift apart, a
// gap on one surface but not the other is a Law-10 false-clean.

#[test]
fn all_has_twenty_kinds() {
    assert_eq!(
        CoverageGapKind::ALL.len(),
        20,
        "the canonical coverage-gap set must have exactly 20 categories"
    );
}

#[test]
fn all_kinds_are_distinct() {
    let mut seen: Vec<CoverageGapKind> = Vec::new();
    for kind in CoverageGapKind::ALL {
        assert!(
            !seen.contains(&kind),
            "{kind:?} appears more than once in CoverageGapKind::ALL"
        );
        seen.push(kind);
    }
}

#[test]
fn every_kind_is_nonzero_on_all_ones() {
    let counts = all_ones();
    for kind in CoverageGapKind::ALL {
        assert!(
            kind.count(&counts) > 0,
            "{kind:?} has a zero count when every counter is set: its field is unwired"
        );
    }
}

#[test]
fn every_kind_is_zero_on_empty() {
    let counts = CoverageCounts::default();
    for kind in CoverageGapKind::ALL {
        assert_eq!(
            kind.count(&counts),
            0,
            "{kind:?} must be zero for an all-zero snapshot"
        );
    }
}

#[test]
fn fail_severity_set_is_exact() {
    use CoverageGapKind::*;
    for kind in [
        ScannerStructuredParseFailure,
        SourceError,
        NonBinaryUnreadable,
        GitObjectUnreadable,
        ArchiveTruncated,
        BinarySectionNameUnresolved,
        SourceTruncated,
        StructuredSourceParseFailure,
        ArchiveDuplicateScanUnavailable,
        GitLfsPointer,
        BinaryDegraded,
        BinaryUnreadable,
        // KH-1347: line identity wrong → FAIL so incomplete exit shares this set.
        ScannerLineOffsetMismatch,
    ] {
        assert_eq!(
            kind.severity(),
            CoverageSeverity::Fail,
            "{kind:?} is a genuine coverage miss and must render as FAIL (red)"
        );
    }
}

#[test]
fn warn_severity_set_is_exact() {
    use CoverageGapKind::*;
    for kind in [
        OverMaxSize,
        Binary,
        Excluded,
        ScannerStructuredOversizeSkip,
        ScannerDecodeTruncation,
        ScannerInvalidPatternIndexSkip,
        ScannerBoundaryCardinalityMismatch,
    ] {
        assert_eq!(
            kind.severity(),
            CoverageSeverity::Warn,
            "{kind:?} is advisory/partial and must render as WARN (yellow)"
        );
    }
}

#[test]
fn severity_partition_totals_all_kinds() {
    // 12 FAIL + 8 WARN = 20, no kind is left unclassified, and the split is
    // pinned so a future re-classification is a deliberate, reviewed change.
    let fail = CoverageGapKind::ALL
        .iter()
        .filter(|k| k.severity() == CoverageSeverity::Fail)
        .count();
    let warn = CoverageGapKind::ALL
        .iter()
        .filter(|k| k.severity() == CoverageSeverity::Warn)
        .count();
    assert_eq!(fail, 12, "expected 12 FAIL categories, got {fail}");
    assert_eq!(warn, 8, "expected 8 WARN categories, got {warn}");
    assert_eq!(fail + warn, CoverageGapKind::ALL.len());
    assert_eq!(
        CoverageGapKind::fail_class_kinds().count(),
        fail,
        "fail_class_kinds() must match severity()==Fail filter (KH-1410)"
    );
}

/// Daemon `SourceCoverageGaps::fail_class_total` is the source-skip FAIL
/// subset (no binary/scanner/source_errors). Pin it against skip-field FAIL
/// kinds so protocol and CLI incomplete exits cannot diverge on those fields
/// (KH-1463 partial lock).
#[test]
fn daemon_source_coverage_gaps_fail_class_matches_source_skip_fail_kinds() {
    use crate::daemon::protocol::SourceCoverageGaps;
    let gaps = SourceCoverageGaps {
        over_max_size: 1,
        binary: 1,
        unreadable: 2,
        git_object_unreadable: 3,
        archive_truncated: 4,
        binary_section_name_unresolved: 5,
        source_truncated: 6,
        structured_source_parse_failures: 7,
        archive_duplicate_scan_unavailable: 8,
        git_lfs_pointer: 9,
    };
    // WARN fields must not contribute.
    assert_eq!(
        gaps.fail_class_total(),
        2 + 3 + 4 + 5 + 6 + 7 + 8 + 9,
        "daemon fail_class_total must exclude over_max_size and binary"
    );
    assert_eq!(gaps.total(), gaps.fail_class_total() + 1 + 1);
}

/// KH-1410: hand-rolled incomplete-exit sums cannot drift from CoverageGapKind.
#[test]
fn fail_class_total_sums_only_fail_kinds() {
    let counts = all_ones();
    let via_kinds: usize = CoverageGapKind::fail_class_kinds()
        .map(|k| k.count(&counts))
        .sum();
    assert_eq!(counts.fail_class_total(), via_kinds);
    // WARN-only categories must not contribute.
    for kind in CoverageGapKind::ALL {
        if kind.severity() == CoverageSeverity::Warn {
            // all_ones sets every counter to 1, so each WARN kind contributes 1
            // to total but 0 to fail_class_total.
            assert!(
                kind.count(&counts) > 0,
                "{kind:?} should be non-zero in all_ones fixture"
            );
        }
    }
    let warn_sum: usize = CoverageGapKind::ALL
        .iter()
        .filter(|k| k.severity() == CoverageSeverity::Warn)
        .map(|k| k.count(&counts))
        .sum();
    let all_sum: usize = CoverageGapKind::ALL.iter().map(|k| k.count(&counts)).sum();
    assert_eq!(
        counts.fail_class_total() + warn_sum,
        all_sum,
        "FAIL+WARN partition must cover every kind count"
    );
    assert!(
        counts.fail_class_total() < all_sum,
        "WARN categories must be excluded from fail_class_total"
    );
}

#[test]
fn sarif_reasons_are_all_unique() {
    let mut reasons: Vec<&str> = CoverageGapKind::ALL
        .iter()
        .map(|k| k.sarif_reason())
        .collect();
    let total = reasons.len();
    reasons.sort_unstable();
    reasons.dedup();
    assert_eq!(
        reasons.len(),
        total,
        "two kinds share a SARIF reason string"
    );
}

#[test]
fn sarif_reasons_are_all_nonempty() {
    for kind in CoverageGapKind::ALL {
        assert!(
            !kind.sarif_reason().trim().is_empty(),
            "{kind:?} has an empty SARIF reason"
        );
    }
}

#[test]
fn human_reasons_are_all_unique() {
    let mut reasons: Vec<String> = CoverageGapKind::ALL
        .iter()
        .map(|k| k.human_reason(1))
        .collect();
    let total = reasons.len();
    reasons.sort();
    reasons.dedup();
    assert_eq!(
        reasons.len(),
        total,
        "two kinds share a human reason string"
    );
}

#[test]
fn human_reasons_are_all_nonempty() {
    for kind in CoverageGapKind::ALL {
        assert!(
            !kind.human_reason(1).trim().is_empty(),
            "{kind:?} has an empty human reason"
        );
    }
}

#[test]
fn human_reason_embeds_the_count() {
    for kind in CoverageGapKind::ALL {
        let reason = kind.human_reason(4242);
        assert!(
            reason.contains("4242"),
            "{kind:?} human reason must include its count, got {reason:?}"
        );
    }
}

#[test]
fn sarif_summary_is_the_projection_of_all_kinds() {
    // Every kind with a non-zero count, and only those, must appear in the
    // SARIF summary keyed by its exact sarif_reason. This binds the SARIF surface
    // to the canonical set.
    let counts = all_ones();
    let summary = coverage_gap_summary(&counts);
    for kind in CoverageGapKind::ALL {
        assert!(
            summary.iter().any(|(r, _)| r == kind.sarif_reason()),
            "{kind:?} is non-zero on all_ones but its sarif_reason is missing from the summary"
        );
    }
    assert_eq!(
        summary.len(),
        CoverageGapKind::ALL.len(),
        "the SARIF summary must contain exactly one entry per non-zero kind"
    );
}

#[test]
fn both_surfaces_cover_the_identical_kind_set() {
    // The unification invariant: for one snapshot, the kinds the SARIF surface
    // reports are exactly the non-zero kinds the human surface would render. If a
    // kind lived on one surface only, the two counts would disagree.
    let counts = all_ones();
    let summary = coverage_gap_summary(&counts);
    let sarif_reasons: Vec<&str> = summary.iter().map(|(r, _)| r.as_str()).collect();

    let mut rendered = 0usize;
    for kind in CoverageGapKind::ALL {
        let n = kind.count(&counts);
        if n == 0 {
            continue;
        }
        assert!(
            !kind.human_reason(n).trim().is_empty(),
            "{kind:?} non-zero but the human surface renders nothing"
        );
        assert!(
            sarif_reasons.contains(&kind.sarif_reason()),
            "{kind:?} rendered by the human surface but missing from SARIF"
        );
        rendered += 1;
    }
    assert_eq!(
        rendered,
        summary.len(),
        "the human and SARIF surfaces must cover the identical set of kinds"
    );
    assert_eq!(rendered, 20, "all 20 kinds render on the all_ones snapshot");
}
