//! Pins the exact `SkipCounts::total()` contract (#177): `total()` counts ONLY
//! the five WHOLE-FILE skip categories and deliberately EXCLUDES the six
//! partial-coverage signals (git-object-unreadable, binary-section-name-
//! unresolved, source-truncated, structured-source-parse-failure, archive-
//! duplicate-scan-unavailable, git-lfs-pointer). The end-to-end regression
//! suites exercise `total()` incidentally on real scans; none pins WHICH fields
//! feed the sum, so a stray `+ git_lfs_pointer` in the accounting would slip
//! through. These assert the exact arithmetic (Law 6).

use keyhog_sources::SkipCounts;

#[test]
fn total_sums_only_the_five_whole_file_skip_categories() {
    let counts = SkipCounts {
        // Whole-file skips — these five sum into total(): 1+2+4+8+16 = 31.
        over_max_size: 1,
        binary: 2,
        excluded: 4,
        unreadable: 8,
        archive_truncated: 16,
        // Partial-coverage signals — surfaced separately, MUST NOT be in total().
        // Each carries a distinct high bit (>= 32) so any leak into the sum is
        // detectable by the equality below.
        git_object_unreadable: 32,
        binary_section_name_unresolved: 64,
        source_truncated: 128,
        structured_source_parse_failures: 256,
        archive_duplicate_scan_unavailable: 512,
        git_lfs_pointer: 1024,
    };
    // Exactly the five whole-file bits. Had any partial-coverage field leaked in,
    // the sum would carry its distinct high bit and fail this equality. (The
    // exhaustive literal is deliberate: a new SkipCounts field will break
    // compilation here, forcing a conscious decision about total() membership.)
    assert_eq!(counts.total(), 31);
}

#[test]
fn total_of_default_is_zero() {
    assert_eq!(SkipCounts::default().total(), 0);
}

#[test]
fn each_whole_file_category_contributes_independently() {
    // One whole-file field at a time — each adds exactly its value.
    assert_eq!(
        SkipCounts {
            over_max_size: 5,
            ..Default::default()
        }
        .total(),
        5
    );
    assert_eq!(
        SkipCounts {
            binary: 5,
            ..Default::default()
        }
        .total(),
        5
    );
    assert_eq!(
        SkipCounts {
            excluded: 5,
            ..Default::default()
        }
        .total(),
        5
    );
    assert_eq!(
        SkipCounts {
            unreadable: 5,
            ..Default::default()
        }
        .total(),
        5
    );
    assert_eq!(
        SkipCounts {
            archive_truncated: 5,
            ..Default::default()
        }
        .total(),
        5
    );
    // A partial-coverage field alone contributes NOTHING to total().
    assert_eq!(
        SkipCounts {
            git_lfs_pointer: 5,
            ..Default::default()
        }
        .total(),
        0
    );
    assert_eq!(
        SkipCounts {
            source_truncated: 5,
            ..Default::default()
        }
        .total(),
        0
    );
}
