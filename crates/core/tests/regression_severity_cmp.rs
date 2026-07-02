//! Regression: `Severity` total-order (`Ord`/`PartialOrd`) *compare + max*
//! axis.
//!
//! This file is deliberately scoped to the operations a scanner actually
//! performs on the order relation once it exists: reducing a *set* of
//! severities to its worst (`Iterator::max`) or least (`Iterator::min`),
//! clamping a tier into a window, sorting descending (`cmp::Reverse`), the
//! ascending iteration order of a `BTreeSet<Severity>`, threshold-count
//! filters (`>= Medium`, `< Low`), and the algebraic laws a `derive(Ord)`
//! MUST satisfy (antisymmetry, totality, transitivity) checked exhaustively
//! over every pair/triple.
//!
//! It is intentionally disjoint from the sibling suites:
//!   * `regression_severity_ordering.rs` asserts pairwise `std::cmp::max`,
//!     ascending `sort()`, `partial_cmp`, and the display/serde wire forms.
//!   * `regression_severity_downgrade_threshold.rs` owns `downgrade_one` and
//!     the `severity_lte` suppression ladder.
//! Nothing here re-asserts those contracts; every test below exercises an
//! operation (iterator-reduce over a collection, `clamp`, `Reverse`,
//! `BTreeSet`, exhaustive triple transitivity) that appears in NEITHER
//! sibling. Declaration order under test: Info < ClientSafe < Low < Medium
//! < High < Critical.

use std::cmp::{Ordering, Reverse};
use std::collections::BTreeSet;

use keyhog_core::Severity;

/// Canonical low-to-high order. Local source of truth; the crate-private
/// `Severity::ORDERED` table is not importable from an integration test, so
/// this asserts the same declaration order independently.
const ORDER: [Severity; 6] = [
    Severity::Info,
    Severity::ClientSafe,
    Severity::Low,
    Severity::Medium,
    Severity::High,
    Severity::Critical,
];

// ---------------------------------------------------------------------------
// Iterator reduce over a SET (not pairwise): worst / least of a collection.
// ---------------------------------------------------------------------------

#[test]
fn iterator_max_over_full_shuffled_set_is_critical() {
    let set = vec![
        Severity::High,
        Severity::Info,
        Severity::Critical,
        Severity::ClientSafe,
        Severity::Medium,
        Severity::Low,
    ];
    assert_eq!(set.into_iter().max(), Some(Severity::Critical));
}

#[test]
fn iterator_min_over_full_shuffled_set_is_info() {
    let set = vec![
        Severity::High,
        Severity::Critical,
        Severity::ClientSafe,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
    assert_eq!(set.into_iter().min(), Some(Severity::Info));
}

#[test]
fn iterator_max_min_of_empty_collection_is_none() {
    // Boundary: reducing an empty batch yields no tier, not a defaulted one.
    let empty: Vec<Severity> = Vec::new();
    assert_eq!(empty.iter().copied().max(), None);
    assert_eq!(empty.iter().copied().min(), None);
}

#[test]
fn max_of_set_without_critical_is_high_min_is_client_safe() {
    // Excludes both extremes to prove the reduce tracks the actual contents,
    // not a hardcoded top/bottom.
    let set = vec![
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::ClientSafe,
    ];
    assert_eq!(set.iter().copied().max(), Some(Severity::High));
    assert_eq!(set.iter().copied().min(), Some(Severity::ClientSafe));
}

#[test]
fn worst_of_batch_reduces_to_dominating_tier() {
    // Models "escalate a batch of findings to its worst tier".
    // A lone Critical dominates every lower tier around it.
    let dominated = vec![
        Severity::Info,
        Severity::Low,
        Severity::Critical,
        Severity::ClientSafe,
        Severity::Medium,
    ];
    assert_eq!(dominated.into_iter().max(), Some(Severity::Critical));

    // No Critical/High present: worst is the Medium.
    let capped = vec![
        Severity::Low,
        Severity::ClientSafe,
        Severity::Medium,
        Severity::Info,
    ];
    assert_eq!(capped.into_iter().max(), Some(Severity::Medium));

    // All-Info batch: worst is still Info (fold identity holds).
    let flat = vec![Severity::Info, Severity::Info, Severity::Info];
    assert_eq!(flat.into_iter().max(), Some(Severity::Info));
}

// ---------------------------------------------------------------------------
// clamp: window each tier into [min, max].
// ---------------------------------------------------------------------------

#[test]
fn clamp_windows_each_tier_into_low_high_bounds() {
    // Above the window clamps down to High; below clamps up to Low; inside is
    // returned unchanged.
    assert_eq!(
        Severity::Critical.clamp(Severity::Low, Severity::High),
        Severity::High
    );
    assert_eq!(
        Severity::Info.clamp(Severity::Low, Severity::High),
        Severity::Low
    );
    assert_eq!(
        Severity::ClientSafe.clamp(Severity::Low, Severity::High),
        Severity::Low
    );
    assert_eq!(
        Severity::Medium.clamp(Severity::Low, Severity::High),
        Severity::Medium
    );
    // Full-range window leaves every tier untouched.
    for tier in ORDER {
        assert_eq!(
            tier.clamp(Severity::Info, Severity::Critical),
            tier,
            "{tier:?} must be unchanged by a full-range clamp"
        );
    }
}

// ---------------------------------------------------------------------------
// Descending sort via cmp::Reverse (distinct from the sibling's ascending sort).
// ---------------------------------------------------------------------------

#[test]
fn reverse_sort_yields_high_to_low_order() {
    let mut set = vec![
        Severity::Medium,
        Severity::Critical,
        Severity::Info,
        Severity::High,
        Severity::Low,
        Severity::ClientSafe,
    ];
    set.sort_by_key(|s| Reverse(*s));
    assert_eq!(
        set,
        vec![
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::ClientSafe,
            Severity::Info,
        ]
    );
}

#[test]
fn sort_by_explicit_descending_cmp_matches_reverse() {
    let mut set = vec![
        Severity::Low,
        Severity::Critical,
        Severity::ClientSafe,
        Severity::High,
    ];
    set.sort_by(|a, b| b.cmp(a));
    assert_eq!(
        set,
        vec![
            Severity::Critical,
            Severity::High,
            Severity::Low,
            Severity::ClientSafe,
        ]
    );
}

// ---------------------------------------------------------------------------
// BTreeSet: Ord drives ascending, deduplicated iteration order.
// ---------------------------------------------------------------------------

#[test]
fn btreeset_iterates_ascending_and_dedupes() {
    // Insert out of order and with duplicates; BTreeSet must yield each tier
    // once, ascending.
    let mut tree: BTreeSet<Severity> = BTreeSet::new();
    for s in [
        Severity::High,
        Severity::Info,
        Severity::High, // dup
        Severity::Critical,
        Severity::Low,
        Severity::Info, // dup
        Severity::Medium,
        Severity::ClientSafe,
    ] {
        tree.insert(s);
    }
    assert_eq!(tree.len(), 6, "duplicates must collapse to 6 unique tiers");
    let collected: Vec<Severity> = tree.iter().copied().collect();
    assert_eq!(collected, ORDER.to_vec());
    // First is the least tier, last is the greatest.
    assert_eq!(tree.iter().next().copied(), Some(Severity::Info));
    assert_eq!(tree.iter().next_back().copied(), Some(Severity::Critical));
}

// ---------------------------------------------------------------------------
// Threshold-count filters over the full tier set.
// ---------------------------------------------------------------------------

#[test]
fn count_of_tiers_at_or_above_medium_is_three() {
    let at_or_above: Vec<Severity> = ORDER
        .iter()
        .copied()
        .filter(|s| *s >= Severity::Medium)
        .collect();
    assert_eq!(at_or_above.len(), 3);
    assert_eq!(
        at_or_above,
        vec![Severity::Medium, Severity::High, Severity::Critical]
    );
    // The worst of that filtered set is Critical.
    assert_eq!(at_or_above.into_iter().max(), Some(Severity::Critical));
}

#[test]
fn count_of_tiers_strictly_below_low_is_two() {
    let below: Vec<Severity> = ORDER
        .iter()
        .copied()
        .filter(|s| *s < Severity::Low)
        .collect();
    assert_eq!(below.len(), 2);
    assert_eq!(below, vec![Severity::Info, Severity::ClientSafe]);
    // Least of everything below Low is Info; the boundary Low itself is excluded.
    assert!(!below.contains(&Severity::Low));
    assert_eq!(below.into_iter().min(), Some(Severity::Info));
}

// ---------------------------------------------------------------------------
// Boundary: >=/<= at equality, and the just-adjacent asymmetric pair.
// ---------------------------------------------------------------------------

#[test]
fn ge_and_le_behave_at_equality_and_adjacency() {
    // Reflexive boundary: a tier is both >= and <= itself, never strictly.
    assert!(Severity::Medium >= Severity::Medium);
    assert!(Severity::Medium <= Severity::Medium);
    assert!(!(Severity::Medium > Severity::Medium));
    assert!(!(Severity::Medium < Severity::Medium));
    // Adjacent asymmetry across the Low/Medium boundary.
    assert!(Severity::Medium >= Severity::Low);
    assert!(Severity::Medium > Severity::Low);
    assert!(!(Severity::Low >= Severity::Medium));
    assert!(Severity::Low <= Severity::Medium);
}

// ---------------------------------------------------------------------------
// Algebraic laws of the total order, checked EXHAUSTIVELY.
// ---------------------------------------------------------------------------

#[test]
fn ord_is_total_and_antisymmetric_over_every_pair() {
    // For every ordered pair exactly one of <, ==, > holds, and cmp(a,b) is
    // the reverse of cmp(b,a). 36 pairs.
    let mut pairs = 0;
    for &a in ORDER.iter() {
        for &b in ORDER.iter() {
            pairs += 1;
            let trichotomy = (a < b) as u8 + (a == b) as u8 + (a > b) as u8;
            assert_eq!(trichotomy, 1, "trichotomy broken for {a:?} vs {b:?}");
            assert_eq!(
                a.cmp(&b),
                b.cmp(&a).reverse(),
                "antisymmetry broken for {a:?} vs {b:?}"
            );
            if a == b {
                assert_eq!(a.cmp(&b), Ordering::Equal);
            }
        }
    }
    assert_eq!(pairs, 36);
}

#[test]
fn ord_is_transitive_over_every_triple() {
    // a < b && b < c  =>  a < c, checked over all 216 triples.
    let mut triples = 0;
    for &a in ORDER.iter() {
        for &b in ORDER.iter() {
            for &c in ORDER.iter() {
                triples += 1;
                if a < b && b < c {
                    assert!(a < c, "transitivity broken: {a:?} < {b:?} < {c:?}");
                }
            }
        }
    }
    assert_eq!(triples, 216);
    // Spot anchor of the transitive chain end to end.
    assert!(Severity::Info < Severity::Medium && Severity::Medium < Severity::Critical);
    assert!(Severity::Info < Severity::Critical);
}
