//! #113 perf: `ScanState::into_matches` collapsed three allocating stable
//! `sort()` passes (each merge-sort allocates an ~n/2 scratch buffer) into two
//! non-allocating `sort_unstable` passes by folding the best-first tiebreak into
//! the identity-grouping comparator.
//!
//! That rewrite is only sound because of a precise ordering invariant, and these
//! tests LOCK it so the optimization can never silently regress output:
//!
//!   1. ORDER-INDEPENDENCE. The old leading `sort()` made the identity grouping
//!      *stable*, so the best entry of each duplicate run came first "for free".
//!      The new code instead orders by `(identity, RawMatch::Ord)`, so an
//!      UNSTABLE sort still puts the best first - but only if the result is
//!      genuinely independent of input order. If it were not, an unstable sort
//!      would be a nondeterminism bug. So the central lock is: the same multiset
//!      of matches, fed in any order, drains to a byte-identical `Vec`.
//!
//!   2. TOTALITY. The final output sort is also unstable, which is byte-identical
//!      to a stable sort ONLY because `RawMatch::Ord` is total with respect to
//!      the dedup identity: Ord-Equal implies same (detector, credential, offset)
//!      implies same identity. After dedup every survivor has a distinct
//!      identity, so no two survivors can compare Equal, so the sorted order is
//!      uniquely determined. These tests assert exactly that no two survivors are
//!      Ord-Equal.
//!
//! The seam is the public `scan_state_drain`, which pushes every match through
//! the real `ScanState::push_match` heap and then `into_matches`. Every test uses
//! a `LIMIT` far above its match count so the per-chunk cap never evicts - this
//! isolates the dedup+sort path under test from heap eviction.

use keyhog_core::{MatchLocation, RawMatch, SensitiveString, Severity};
use keyhog_scanner::testing::scan_state_drain;

/// Capacity high enough that `push_match`'s cap never evicts in these tests, so
/// `into_matches` is the only transform exercised.
const LIMIT: usize = 100_000;

/// Build a `RawMatch`. `credential_hash` is left zeroed: the dedup identity is
/// `(detector_id, credential, offset)` and `RawMatch::Ord` never consults the
/// hash, so it plays no role here, and equal credentials get equal (zero)
/// hashes - keeping full-struct `Eq` faithful for the order-independence checks.
fn m(detector: &str, cred: &str, offset: usize, conf: f64, sev: Severity, line: usize) -> RawMatch {
    RawMatch {
        detector_id: detector.into(),
        detector_name: detector.into(),
        service: "svc".into(),
        severity: sev,
        credential: SensitiveString::from(cred),
        credential_hash: [0u8; 32].into(),
        companions: std::collections::HashMap::new(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some("f.env".into()),
            line: Some(line),
            offset,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: Some(conf),
    }
}

/// Convenience for the common case (High severity, line derived from offset).
fn hi(detector: &str, cred: &str, offset: usize, conf: f64) -> RawMatch {
    m(detector, cred, offset, conf, Severity::High, offset + 1)
}

/// A stable, allocation-faithful fingerprint of a drained result for comparing
/// two orderings: the full ordered tuple of identity + ranking fields.
fn shape(matches: &[RawMatch]) -> Vec<(String, String, usize, u64, String, Option<usize>)> {
    matches
        .iter()
        .map(|x| {
            (
                x.detector_id.to_string(),
                x.credential.as_ref().to_string(),
                x.location.offset,
                x.confidence.unwrap_or(0.0).to_bits(),
                format!("{:?}", x.severity),
                x.location.line,
            )
        })
        .collect()
}

/// All permutations of `items` (n! - only call with small n).
fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut out = Vec::new();
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let head = rest.remove(i);
        for mut tail in permutations(&rest) {
            tail.insert(0, head.clone());
            out.push(tail);
        }
    }
    out
}

// ── Group A: order-independence (the core soundness invariant) ───────────────

#[test]
fn output_identical_for_reversed_input_order() {
    let base = vec![
        hi("aws", "AKIAforward1", 10, 0.8),
        hi("gh", "ghp_token_two", 20, 0.6),
        hi("aws", "AKIAforward1", 10, 0.95), // duplicate identity, higher conf
        hi("slack", "xoxb-three", 30, 0.7),
    ];
    let mut reversed = base.clone();
    reversed.reverse();

    let forward = scan_state_drain(base, LIMIT);
    let backward = scan_state_drain(reversed, LIMIT);
    assert_eq!(
        forward, backward,
        "draining the same matches in reversed order must produce a byte-identical result"
    );
}

#[test]
fn output_identical_for_rotated_input_order() {
    let base = vec![
        hi("a", "alpha", 1, 0.5),
        hi("b", "bravo", 2, 0.9),
        hi("c", "charlie", 3, 0.1),
        hi("d", "delta", 4, 0.7),
        hi("e", "echo", 5, 0.3),
    ];
    let canonical = scan_state_drain(base.clone(), LIMIT);
    for k in 1..base.len() {
        let mut rotated = base.clone();
        rotated.rotate_left(k);
        assert_eq!(
            scan_state_drain(rotated, LIMIT),
            canonical,
            "rotation by {k} must not change the drained result"
        );
    }
}

#[test]
fn output_identical_across_all_permutations_of_distinct_matches() {
    let base = vec![
        hi("a", "alpha", 1, 0.50),
        hi("b", "bravo", 2, 0.90),
        hi("c", "charlie", 3, 0.10),
        hi("d", "delta", 4, 0.70),
    ];
    let canonical = shape(&scan_state_drain(base.clone(), LIMIT));
    for perm in permutations(&base) {
        assert_eq!(
            shape(&scan_state_drain(perm, LIMIT)),
            canonical,
            "every input permutation of distinct matches must drain identically"
        );
    }
}

#[test]
fn output_identical_across_all_permutations_with_identity_collisions() {
    // Three of these share the (detector, credential, offset) identity at
    // differing confidences; the survivor must be the max regardless of order.
    let base = vec![
        hi("aws", "AKIAdup", 7, 0.20),
        hi("aws", "AKIAdup", 7, 0.95),
        hi("aws", "AKIAdup", 7, 0.55),
        hi("gh", "ghp_other", 9, 0.40),
    ];
    let canonical = shape(&scan_state_drain(base.clone(), LIMIT));
    for perm in permutations(&base) {
        assert_eq!(
            shape(&scan_state_drain(perm, LIMIT)),
            canonical,
            "identity-colliding inputs must dedup order-independently"
        );
    }
    // And the canonical survivor really is the 0.95 entry (one survivor for the dup).
    let drained = scan_state_drain(base, LIMIT);
    let aws: Vec<f64> = drained
        .iter()
        .filter(|x| &*x.detector_id == "aws")
        .map(|x| x.confidence.unwrap())
        .collect();
    assert_eq!(aws, vec![0.95], "the colliding identity keeps exactly its max-confidence entry");
}

#[test]
fn large_shuffle_with_many_collisions_is_order_independent() {
    // 60 distinct identities, each appearing 3x at different confidences, plus
    // interleaving so a naive order-sensitive dedup would diverge.
    let mut base = Vec::new();
    for id in 0..60usize {
        for rep in 0..3u32 {
            let conf = 0.1 + (f64::from(rep) * 0.3); // 0.1, 0.4, 0.7
            base.push(hi("det", &format!("cred{id:03}"), id * 4, conf));
        }
    }
    let canonical = shape(&scan_state_drain(base.clone(), LIMIT));

    // Two deterministic, distinct reorderings (reverse, and an odd/even split).
    let mut reversed = base.clone();
    reversed.reverse();
    assert_eq!(shape(&scan_state_drain(reversed, LIMIT)), canonical);

    let (evens, odds): (Vec<_>, Vec<_>) =
        base.iter().cloned().enumerate().partition(|(i, _)| i % 2 == 0);
    let mut split: Vec<RawMatch> = odds.into_iter().map(|(_, x)| x).collect();
    split.extend(evens.into_iter().map(|(_, x)| x));
    assert_eq!(shape(&scan_state_drain(split, LIMIT)), canonical);

    // Each identity must keep exactly its 0.7 max.
    let drained = scan_state_drain(base, LIMIT);
    assert_eq!(drained.len(), 60, "60 distinct identities survive");
    assert!(
        drained.iter().all(|x| (x.confidence.unwrap() - 0.7).abs() < 1e-9),
        "every survivor is the 0.7 max of its 3-way collision"
    );
}

#[test]
fn best_survivor_independent_of_its_position_in_the_input() {
    // The max-confidence duplicate is placed first, middle, and last; the result
    // must be identical every time.
    let best = hi("aws", "AKIAx", 5, 0.99);
    let mid = hi("aws", "AKIAx", 5, 0.50);
    let low = hi("aws", "AKIAx", 5, 0.10);

    let first = scan_state_drain(vec![best.clone(), mid.clone(), low.clone()], LIMIT);
    let middle = scan_state_drain(vec![mid.clone(), best.clone(), low.clone()], LIMIT);
    let last = scan_state_drain(vec![low, mid, best], LIMIT);

    assert_eq!(first, middle);
    assert_eq!(middle, last);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].confidence.unwrap(), 0.99);
}

// ── Group B: dedup correctness ───────────────────────────────────────────────

#[test]
fn exact_duplicate_collapses_to_one() {
    let one = hi("aws", "AKIAsame", 3, 0.8);
    let drained = scan_state_drain(vec![one.clone(), one], LIMIT);
    assert_eq!(drained.len(), 1, "two byte-identical matches dedup to one");
}

#[test]
fn three_way_duplicate_keeps_max_confidence() {
    let drained = scan_state_drain(
        vec![
            hi("d", "cred", 4, 0.30),
            hi("d", "cred", 4, 0.85),
            hi("d", "cred", 4, 0.60),
        ],
        LIMIT,
    );
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].confidence.unwrap(), 0.85);
}

#[test]
fn worst_of_a_duplicate_pair_is_dropped() {
    let drained = scan_state_drain(
        vec![hi("d", "cred", 4, 0.20), hi("d", "cred", 4, 0.90)],
        LIMIT,
    );
    assert_eq!(drained.len(), 1);
    assert!(
        (drained[0].confidence.unwrap() - 0.90).abs() < 1e-9,
        "the 0.20 entry must be gone; only the 0.90 survives"
    );
}

#[test]
fn distinct_credentials_never_merge() {
    let drained = scan_state_drain(
        vec![hi("d", "cred_a", 4, 0.8), hi("d", "cred_b", 4, 0.8)],
        LIMIT,
    );
    assert_eq!(drained.len(), 2, "same detector+offset but different credential are distinct");
}

#[test]
fn distinct_offsets_never_merge() {
    let drained = scan_state_drain(
        vec![hi("d", "cred", 4, 0.8), hi("d", "cred", 9, 0.8)],
        LIMIT,
    );
    assert_eq!(drained.len(), 2, "same detector+credential at different offsets are distinct");
    let offsets: Vec<usize> = drained.iter().map(|x| x.location.offset).collect();
    assert_eq!(offsets, vec![4, 9], "distinct-offset survivors are ordered by offset ascending");
}

#[test]
fn distinct_detectors_never_merge() {
    let drained = scan_state_drain(
        vec![hi("det_a", "cred", 4, 0.8), hi("det_b", "cred", 4, 0.8)],
        LIMIT,
    );
    assert_eq!(drained.len(), 2, "same credential+offset under different detectors are distinct");
}

#[test]
fn all_identical_inputs_collapse_to_single() {
    let one = hi("d", "cred", 4, 0.5);
    let drained = scan_state_drain(vec![one.clone(), one.clone(), one.clone(), one.clone(), one], LIMIT);
    assert_eq!(drained.len(), 1, "five identical matches collapse to exactly one");
}

#[test]
fn matches_differing_only_in_line_dedup_to_one() {
    // line is NOT part of the identity, so two matches at the same
    // (detector, credential, offset) but different reported line are duplicates.
    let drained = scan_state_drain(
        vec![
            m("d", "cred", 4, 0.8, Severity::High, 11),
            m("d", "cred", 4, 0.8, Severity::High, 22),
        ],
        LIMIT,
    );
    assert_eq!(drained.len(), 1, "line is not an identity field; these dedup");
}

// ── Group C: best-first output ordering ──────────────────────────────────────

#[test]
fn output_sorted_descending_by_confidence() {
    let drained = scan_state_drain(
        vec![
            hi("a", "alpha", 1, 0.20),
            hi("b", "bravo", 2, 0.90),
            hi("c", "charlie", 3, 0.55),
        ],
        LIMIT,
    );
    let confs: Vec<f64> = drained.iter().map(|x| x.confidence.unwrap()).collect();
    assert_eq!(confs, vec![0.90, 0.55, 0.20], "output is highest-confidence first");
}

#[test]
fn equal_confidence_breaks_by_severity_descending() {
    let drained = scan_state_drain(
        vec![
            m("a", "low_sev", 1, 0.7, Severity::Low, 1),
            m("b", "crit_sev", 2, 0.7, Severity::Critical, 2),
            m("c", "med_sev", 3, 0.7, Severity::Medium, 3),
        ],
        LIMIT,
    );
    let creds: Vec<&str> = drained.iter().map(|x| x.credential.as_ref()).collect();
    assert_eq!(
        creds,
        vec!["crit_sev", "med_sev", "low_sev"],
        "equal confidence orders Critical > Medium > Low"
    );
}

#[test]
fn equal_confidence_and_severity_break_by_detector_id_ascending() {
    let drained = scan_state_drain(
        vec![
            hi("zeta", "z", 1, 0.7),
            hi("alpha", "a", 2, 0.7),
            hi("mike", "m", 3, 0.7),
        ],
        LIMIT,
    );
    let ids: Vec<&str> = drained.iter().map(|x| &*x.detector_id).collect();
    assert_eq!(ids, vec!["alpha", "mike", "zeta"], "tie breaks by detector_id ascending");
}

#[test]
fn equal_through_credential_breaks_by_offset_ascending() {
    // Same detector + same credential at different offsets => distinct identities
    // whose only differing Ord key (after conf/sev/detector/credential) is offset.
    let drained = scan_state_drain(
        vec![
            hi("d", "samecred", 30, 0.7),
            hi("d", "samecred", 10, 0.7),
            hi("d", "samecred", 20, 0.7),
        ],
        LIMIT,
    );
    let offsets: Vec<usize> = drained.iter().map(|x| x.location.offset).collect();
    assert_eq!(offsets, vec![10, 20, 30], "final tie resolves by offset ascending");
}

// ── Group D: boundaries / fast path ──────────────────────────────────────────

#[test]
fn empty_input_yields_empty() {
    assert!(scan_state_drain(Vec::new(), LIMIT).is_empty());
}

#[test]
fn single_match_passes_through_unchanged() {
    let one = hi("d", "only", 4, 0.42);
    let drained = scan_state_drain(vec![one.clone()], LIMIT);
    assert_eq!(drained, vec![one], "the len<=1 fast path returns the single match verbatim");
}

#[test]
fn single_match_with_none_confidence_passes_through() {
    let mut one = hi("d", "only", 4, 0.0);
    one.confidence = None;
    let drained = scan_state_drain(vec![one.clone()], LIMIT);
    assert_eq!(drained, vec![one]);
}

#[test]
fn two_distinct_matches_both_survive_sorted() {
    let drained = scan_state_drain(
        vec![hi("d", "low", 1, 0.2), hi("d", "high", 2, 0.9)],
        LIMIT,
    );
    assert_eq!(drained.len(), 2);
    assert_eq!(drained[0].credential.as_ref(), "high", "best-first even at n=2");
    assert_eq!(drained[1].credential.as_ref(), "low");
}

// ── Group E: None-confidence handling + determinism ──────────────────────────

#[test]
fn none_confidence_sorts_after_any_scored_match() {
    let mut none_match = hi("d", "noconf", 9, 0.0);
    none_match.confidence = None;
    let drained = scan_state_drain(
        vec![none_match, hi("d", "scored", 1, 0.05)],
        LIMIT,
    );
    assert_eq!(
        drained[0].credential.as_ref(),
        "scored",
        "a Some(0.05) match outranks a None (which sorts as 0.0)"
    );
    assert_eq!(drained[1].credential.as_ref(), "noconf");
}

#[test]
fn duplicate_none_vs_some_keeps_the_scored_entry() {
    // Same identity: one None, one Some(0.5). None sorts as 0.0, so Some(0.5) is
    // "better" and must be the survivor.
    let mut none_match = m("d", "cred", 4, 0.0, Severity::High, 5);
    none_match.confidence = None;
    let some_match = m("d", "cred", 4, 0.5, Severity::High, 5);
    let drained = scan_state_drain(vec![none_match, some_match], LIMIT);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].confidence, Some(0.5), "the scored duplicate wins over the None one");
}

#[test]
fn repeated_drain_is_deterministic() {
    let base = vec![
        hi("a", "alpha", 1, 0.5),
        hi("b", "bravo", 2, 0.5),
        hi("a", "alpha", 1, 0.9),
        hi("c", "charlie", 3, 0.5),
    ];
    let first = scan_state_drain(base.clone(), LIMIT);
    let second = scan_state_drain(base, LIMIT);
    assert_eq!(first, second, "draining the same input twice is byte-identical");
}

// ── Group F: totality premise that makes the unstable final sort sound ────────

#[test]
fn no_two_survivors_compare_equal_under_ord() {
    // The final sort is unstable, which equals a stable sort only if survivors
    // are pairwise Ord-distinct (Ord-Equal implies same identity implies deduped).
    let drained = scan_state_drain(
        vec![
            hi("a", "alpha", 1, 0.7),
            hi("b", "bravo", 1, 0.7), // same conf/sev/offset, different detector+cred
            hi("a", "alpha", 1, 0.7), // exact dup of the first
            hi("c", "charlie", 2, 0.7),
            hi("a", "alpha2", 1, 0.7), // same detector+offset, different cred
        ],
        LIMIT,
    );
    for i in 0..drained.len() {
        for j in (i + 1)..drained.len() {
            assert_ne!(
                drained[i].cmp(&drained[j]),
                std::cmp::Ordering::Equal,
                "survivors {i} and {j} compare Ord-Equal - the unstable output sort would be \
                 nondeterministic"
            );
            assert_ne!(drained[i], drained[j], "no two survivors are fully equal");
        }
    }
}

#[test]
fn survivors_are_strictly_descending_under_ord() {
    let drained = scan_state_drain(
        vec![
            hi("a", "alpha", 1, 0.30),
            hi("b", "bravo", 2, 0.90),
            hi("c", "charlie", 3, 0.60),
            hi("d", "delta", 4, 0.90), // ties bravo on conf, breaks on detector/cred
        ],
        LIMIT,
    );
    for win in drained.windows(2) {
        assert_eq!(
            win[0].cmp(&win[1]),
            std::cmp::Ordering::Less,
            "each survivor strictly precedes the next under RawMatch::Ord (best-first, no ties)"
        );
    }
}

#[test]
fn dense_collisions_preserve_one_survivor_per_identity() {
    // A stress mix: 4 identities, each duplicated 5x with shuffled confidences,
    // interleaved. Exactly 4 survivors, each the per-identity max.
    let mut input = Vec::new();
    let confs = [0.10, 0.55, 0.33, 0.99, 0.42];
    for round in 0..5 {
        for id in 0..4usize {
            input.push(hi("det", &format!("c{id}"), id * 3, confs[(round + id) % confs.len()]));
        }
    }
    let drained = scan_state_drain(input, LIMIT);
    assert_eq!(drained.len(), 4, "4 identities collapse to 4 survivors");
    assert!(
        drained.iter().all(|x| (x.confidence.unwrap() - 0.99).abs() < 1e-9),
        "every survivor is the 0.99 max present in its identity's collision set"
    );
}
