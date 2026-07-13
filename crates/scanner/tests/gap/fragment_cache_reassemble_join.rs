//! Gap test: cross-chunk fragment reassembly output is exact and deterministic.
//!
//! The reassembly loop glues each near same-path fragment pair via a
//! `Zeroizing<String>`. That string is now built with
//! `String::with_capacity(f1.len + f2.len)` instead of growing from empty 
//! a Law-7 single-allocation fix that also avoids an intermediate realloc
//! leaving an un-zeroed plaintext copy of the first fragment on the heap. The
//! glued content and sorted emission order must be byte-for-byte unchanged,
//! pinned here on exact values.

use keyhog_scanner::testing::fragment_reassemble_for_test;

#[test]
fn near_same_path_fragments_join_in_sorted_order() {
    // Two fragments, same prefix + same path, one line apart -> both ordered
    // joins are produced and emitted sorted by the glued bytes.
    let joins = fragment_reassemble_for_test(&[
        ("aws", "AKIA1111", 1, Some("a.env")),
        ("aws", "AKIA2222", 2, Some("a.env")),
    ]);
    assert_eq!(
        joins,
        vec![
            "AKIA1111AKIA2222".to_string(),
            "AKIA2222AKIA1111".to_string(),
        ],
        "near same-path fragments must glue both orderings, sorted by glued bytes"
    );
}

#[test]
fn fragments_beyond_the_100_line_window_do_not_join() {
    // Same prefix + path (so they share a cluster) but 200 lines apart: the
    // reassembly window is strictly < 100 lines, so nothing glues.
    let joins = fragment_reassemble_for_test(&[
        ("aws", "AKIA1111", 1, Some("a.env")),
        ("aws", "AKIA2222", 201, Some("a.env")),
    ]);
    assert_eq!(
        joins,
        Vec::<String>::new(),
        "fragments 200 lines apart exceed the < 100-line reassembly window"
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one in-window join and one out-of-window skip; these
// SWEEP the reassembly contract. Cluster key is `(prefix, path)`, the pair gate is
// `abs(line diff) < 100`, and every same-cluster ordered pair emits `f1.value +
// f2.value`, sorted by the glued bytes (NOT deduped). So for a same-prefix
// same-path pair within the window the output is EXACTLY the two concatenations
// sorted, for any values, any in-window gap. The window boundary is pinned exact
// (gap 99 glues, gap 100 does not), and a cross-prefix pair never glues (distinct
// clusters). Traced against `record_and_reassemble` (fragment_cache.rs:169-206).
// No proptest before.

use proptest::prelude::*;

/// The two ordered concatenations of a pair, sorted by bytes, what a same-cluster
/// in-window pair must produce. ASCII-alnum values make byte-sort == String-sort.
fn sorted_pair_concats(v1: &str, v2: &str) -> Vec<String> {
    let mut v = vec![format!("{v1}{v2}"), format!("{v2}{v1}")];
    v.sort();
    v
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// Two same-prefix same-path fragments within the < 100-line window glue in
    /// BOTH orderings, sorted by the glued bytes (any values, any in-window gap).
    #[test]
    fn same_path_pair_within_window_glues_both_orderings_sorted(
        v1 in "[A-Za-z0-9]{1,12}",
        v2 in "[A-Za-z0-9]{1,12}",
        gap in 1usize..100,
    ) {
        let joins = fragment_reassemble_for_test(&[
            ("aws", v1.as_str(), 1, Some("a.env")),
            ("aws", v2.as_str(), 1 + gap, Some("a.env")),
        ]);
        prop_assert_eq!(joins, sorted_pair_concats(&v1, &v2));
    }

    /// A gap of 100 or more lines exceeds the window, so nothing glues.
    #[test]
    fn same_path_pair_beyond_window_does_not_glue(
        v1 in "[A-Za-z0-9]{1,12}",
        v2 in "[A-Za-z0-9]{1,12}",
        gap in 100usize..500,
    ) {
        let joins = fragment_reassemble_for_test(&[
            ("aws", v1.as_str(), 1, Some("a.env")),
            ("aws", v2.as_str(), 1 + gap, Some("a.env")),
        ]);
        prop_assert!(joins.is_empty());
    }

    /// The window boundary is EXACT: gap 99 glues (abs diff < 100), gap 100 does not.
    #[test]
    fn window_boundary_is_exactly_under_one_hundred(
        v1 in "[A-Za-z0-9]{2,8}",
        v2 in "[A-Za-z0-9]{2,8}",
    ) {
        let at99 = fragment_reassemble_for_test(&[
            ("aws", v1.as_str(), 1, Some("a.env")),
            ("aws", v2.as_str(), 100, Some("a.env")), // gap 99 -> glues
        ]);
        prop_assert_eq!(at99, sorted_pair_concats(&v1, &v2));
        let at100 = fragment_reassemble_for_test(&[
            ("aws", v1.as_str(), 1, Some("a.env")),
            ("aws", v2.as_str(), 101, Some("a.env")), // gap 100 -> no glue
        ]);
        prop_assert!(at100.is_empty());
    }

    /// Different prefixes land in different clusters, so cross-prefix fragments
    /// never glue even at the same path and adjacent lines.
    #[test]
    fn different_prefix_fragments_never_glue(
        v1 in "[A-Za-z0-9]{1,12}",
        v2 in "[A-Za-z0-9]{1,12}",
    ) {
        let joins = fragment_reassemble_for_test(&[
            ("aws", v1.as_str(), 1, Some("a.env")),
            ("gcp", v2.as_str(), 2, Some("a.env")),
        ]);
        prop_assert!(joins.is_empty());
    }
}
