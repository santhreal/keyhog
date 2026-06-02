//! Regression: fragment-cache reassembled output must be DETERMINISTIC.
//!
//! Source under test:
//!   `crates/scanner/src/multiline/fragment_cache.rs`
//!     - `FragmentCache::record_and_reassemble`          -> `Vec<Zeroizing<String>>`
//!     - `FragmentCache::record_and_reassemble_stamped`  -> `Vec<ReassembledCandidate>`
//!
//! BUG (pre-fix): the per-`(prefix, path)` cluster is a `Vec` ordered by
//! fragment *arrival*. Under a parallel (rayon) scan, sibling chunks race for
//! the per-shard mutex, so the arrival order - and therefore the order the
//! nested `(i, j)` pair loop emits glued candidates in - varies run to run for
//! byte-identical input. The plain variant leaked that order directly into the
//! returned `Vec`; the stamped variant additionally stamped a race-dependent
//! anchor `line` onto each glue. Identical input could thus yield different
//! scan output ordering on different runs.
//!
//! FIX: both methods sort their produced candidates into a canonical,
//! content-derived order before returning (plain: glued bytes; stamped:
//! `(glued bytes, anchor line)`). The *set* of joins is unchanged - only the
//! order is now fixed - so output is reproducible regardless of insert order.
//!
//! Every expected value below is derived by tracing the real source:
//!   * join rule: all ordered pairs (i != j) where `f1.path == f2.path` and
//!     `|f1.line - f2.line| < 100`.
//!   * canonical order: ascending by glued bytes (plain) / `(bytes, line)`
//!     (stamped).
//!   * stamped anchor: glue is `f1.value ++ f2.value`, stamped with `f1.line`.

use keyhog_scanner::fragment_cache::{FragmentCache, ReassembledCandidate, SecretFragment};
use std::sync::{Arc, Barrier};
use zeroize::Zeroizing;

fn frag(prefix: &str, var: &str, value: &str, path: &str, line: usize) -> SecretFragment {
    SecretFragment {
        prefix: prefix.to_string(),
        var_name: var.to_string(),
        value: Zeroizing::new(value.to_string()),
        line,
        path: Some(Arc::from(path)),
    }
}

/// The three same-file fragments used across trials. Distinct, non-overlapping
/// values so every glued string is unique and lengths are equal (no prefix is a
/// prefix of another), which makes byte-ordering of glues unambiguous.
const FRAGS: [(&str, usize); 3] = [("AKIA", 1), ("BBBB", 2), ("CCCC", 3)];

/// Canonical order the FIXED code must emit for the plain variant: all six
/// ordered pairwise glues, ascending by bytes. Derived by hand from FRAGS:
///   AKIABBBB < AKIACCCC < BBBBAKIA < BBBBCCCC < CCCCAKIA < CCCCBBBB
const EXPECTED_PLAIN: [&str; 6] = [
    "AKIABBBB", "AKIACCCC", "BBBBAKIA", "BBBBCCCC", "CCCCAKIA", "CCCCBBBB",
];

/// Stamped canonical order: same glues, each carrying the anchor (f1) line.
/// (glue, anchor_line):
///   AKIABBBB@1, AKIACCCC@1, BBBBAKIA@2, BBBBCCCC@2, CCCCAKIA@3, CCCCBBBB@3
const EXPECTED_STAMPED: [(&str, usize); 6] = [
    ("AKIABBBB", 1),
    ("AKIACCCC", 1),
    ("BBBBAKIA", 2),
    ("BBBBCCCC", 2),
    ("CCCCAKIA", 3),
    ("CCCCBBBB", 3),
];

/// Insert the three fragments in the given order, returning the LAST call's
/// reassembly output (the only call where the cluster holds all three).
fn run_plain_in_order(order: &[usize]) -> Vec<String> {
    let cache = FragmentCache::new(1024);
    let mut last = Vec::new();
    for &k in order {
        let (val, line) = FRAGS[k];
        last = cache
            .record_and_reassemble(frag("p", "V", val, "/a.py", line))
            .into_iter()
            .map(|z| z.as_str().to_string())
            .collect();
    }
    last
}

fn run_stamped_in_order(order: &[usize]) -> Vec<(String, usize)> {
    let cache = FragmentCache::new(1024);
    let mut last: Vec<ReassembledCandidate> = Vec::new();
    for &k in order {
        let (val, line) = FRAGS[k];
        last = cache.record_and_reassemble_stamped(frag("p", "V", val, "/a.py", line));
    }
    last.into_iter()
        .map(|c| (c.value.as_str().to_string(), c.line))
        .collect()
}

// ---------------------------------------------------------------------------
// 1. Insert-order independence (the core determinism property).
//    Every permutation of the three fragments must yield the SAME ordered
//    output. Pre-fix, the orderings below diverged (e.g. inserting C,B,A made
//    the cluster [C,B,A] and the (i,j) loop emitted CCCCBBBB first); the sort
//    collapses them all to EXPECTED_*.
// ---------------------------------------------------------------------------

const PERMS: [[usize; 3]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];

#[test]
fn plain_output_order_is_independent_of_insert_order() {
    let expected: Vec<String> = EXPECTED_PLAIN.iter().map(|s| s.to_string()).collect();
    for perm in PERMS {
        let got = run_plain_in_order(&perm);
        assert_eq!(
            got, expected,
            "plain reassembly order must be canonical for insert order {perm:?}; \
             got {got:?}"
        );
    }
}

#[test]
fn stamped_output_order_is_independent_of_insert_order() {
    let expected: Vec<(String, usize)> = EXPECTED_STAMPED
        .iter()
        .map(|(s, l)| (s.to_string(), *l))
        .collect();
    for perm in PERMS {
        let got = run_stamped_in_order(&perm);
        assert_eq!(
            got, expected,
            "stamped reassembly order (value, anchor-line) must be canonical for \
             insert order {perm:?}; got {got:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Exact canonical content (proving values, not shape).
// ---------------------------------------------------------------------------

#[test]
fn plain_emits_exactly_six_canonical_glues() {
    let got = run_plain_in_order(&[0, 1, 2]);
    assert_eq!(
        got.len(),
        6,
        "three near same-file fragments => 6 ordered pairs"
    );
    assert_eq!(
        got,
        EXPECTED_PLAIN
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        "exact canonical glue sequence"
    );
}

#[test]
fn stamped_anchor_line_is_prefix_fragment_line() {
    let got = run_stamped_in_order(&[0, 1, 2]);
    assert_eq!(got.len(), 6);
    // Glue f1.value ++ f2.value is stamped with f1.line. Spot-check the two
    // ends and a middle entry against the hand-derived table.
    assert_eq!(got[0], ("AKIABBBB".to_string(), 1));
    assert_eq!(got[2], ("BBBBAKIA".to_string(), 2));
    assert_eq!(got[5], ("CCCCBBBB".to_string(), 3));
    assert_eq!(
        got,
        EXPECTED_STAMPED
            .iter()
            .map(|(s, l)| (s.to_string(), *l))
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// 3. PARALLEL insert (the real-world trigger). Fragments are recorded from N
//    OS threads released simultaneously via a Barrier, maximizing per-shard
//    lock-order races. The final cluster contents are order-independent, so a
//    deterministic implementation must return EXPECTED_* on every trial. We
//    snapshot the output of whichever record call observed all three and assert
//    it matches the canonical sequence. Repeated many times to shake out races.
// ---------------------------------------------------------------------------

#[test]
fn parallel_inserts_yield_canonical_plain_order() {
    let expected: Vec<String> = EXPECTED_PLAIN.iter().map(|s| s.to_string()).collect();

    for trial in 0..400 {
        let cache = Arc::new(FragmentCache::new(1024));
        let barrier = Arc::new(Barrier::new(FRAGS.len()));
        let handles: Vec<_> = (0..FRAGS.len())
            .map(|k| {
                let cache = Arc::clone(&cache);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let (val, line) = FRAGS[k];
                    barrier.wait();
                    let out: Vec<String> = cache
                        .record_and_reassemble(frag("p", "V", val, "/a.py", line))
                        .into_iter()
                        .map(|z| z.as_str().to_string())
                        .collect();
                    out
                })
            })
            .collect();

        // The thread whose record call saw the full 3-fragment cluster returns
        // all 6 glues; earlier calls return fewer. Take the full-cluster
        // snapshot and assert it is canonical regardless of which thread won.
        let mut full = None;
        for h in handles {
            let out = h.join().expect("record thread panicked");
            if out.len() == EXPECTED_PLAIN.len() {
                full = Some(out);
            }
        }
        let full = full.expect("one record call must observe the complete cluster");
        assert_eq!(
            full, expected,
            "trial {trial}: parallel-recorded plain reassembly must be canonical, \
             got {full:?}"
        );
    }
}

#[test]
fn parallel_inserts_yield_canonical_stamped_order() {
    let expected: Vec<(String, usize)> = EXPECTED_STAMPED
        .iter()
        .map(|(s, l)| (s.to_string(), *l))
        .collect();

    for trial in 0..400 {
        let cache = Arc::new(FragmentCache::new(1024));
        let barrier = Arc::new(Barrier::new(FRAGS.len()));
        let handles: Vec<_> = (0..FRAGS.len())
            .map(|k| {
                let cache = Arc::clone(&cache);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let (val, line) = FRAGS[k];
                    barrier.wait();
                    let out: Vec<(String, usize)> = cache
                        .record_and_reassemble_stamped(frag("p", "V", val, "/a.py", line))
                        .into_iter()
                        .map(|c| (c.value.as_str().to_string(), c.line))
                        .collect();
                    out
                })
            })
            .collect();

        let mut full = None;
        for h in handles {
            let out = h.join().expect("record thread panicked");
            if out.len() == EXPECTED_STAMPED.len() {
                full = Some(out);
            }
        }
        let full = full.expect("one record call must observe the complete cluster");
        assert_eq!(
            full, expected,
            "trial {trial}: parallel-recorded stamped reassembly (value, line) must be \
             canonical, got {full:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Negative twin: cross-file fragments must NOT join, regardless of order.
//    Different full paths key into different clusters (scoped_key uses the full
//    path), so each file's cluster has a single fragment and never reassembles.
//    Determinism here means: always empty.
// ---------------------------------------------------------------------------

#[test]
fn cross_file_fragments_never_join_in_either_order() {
    for order in [[0usize, 1usize], [1, 0]] {
        let cache = FragmentCache::new(1024);
        let files = [("AKIA", 1usize, "/x/a.py"), ("BBBB", 1usize, "/x/b.py")];
        let mut last = Vec::new();
        for &i in &order {
            let (val, line, path) = files[i];
            last = cache.record_and_reassemble(frag("p", "V", val, path, line));
        }
        assert!(
            last.is_empty(),
            "cross-file fragments must not reassemble (order {order:?}), got {} candidates",
            last.len()
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Boundary: line distance is `< 100` (strict). Two same-file fragments 100
//    lines apart do NOT join; 99 apart DO. Order-independent either way.
// ---------------------------------------------------------------------------

#[test]
fn line_distance_boundary_is_exclusive_100() {
    // 99 apart -> joins (both ordered pairs), canonical by bytes.
    for order in [[0usize, 1usize], [1, 0]] {
        let cache = FragmentCache::new(1024);
        let two = [("AAAAAAAA", 1usize), ("ZZZZZZZZ", 100usize)]; // |1-100| = 99 < 100
        let mut last: Vec<String> = Vec::new();
        for &i in &order {
            let (val, line) = two[i];
            last = cache
                .record_and_reassemble(frag("p", "V", val, "/c.py", line))
                .into_iter()
                .map(|z| z.as_str().to_string())
                .collect();
        }
        assert_eq!(
            last,
            vec![
                "AAAAAAAAZZZZZZZZ".to_string(),
                "ZZZZZZZZAAAAAAAA".to_string()
            ],
            "99-line-apart fragments join in canonical byte order (insert order {order:?})"
        );
    }

    // 100 apart -> no join.
    for order in [[0usize, 1usize], [1, 0]] {
        let cache = FragmentCache::new(1024);
        let two = [("AAAAAAAA", 1usize), ("ZZZZZZZZ", 101usize)]; // |1-101| = 100, not < 100
        let mut last = Vec::new();
        for &i in &order {
            let (val, line) = two[i];
            last = cache.record_and_reassemble(frag("p", "V", val, "/c.py", line));
        }
        assert!(
            last.is_empty(),
            "exactly-100-lines-apart fragments must not join (insert order {order:?}), \
             got {} candidates",
            last.len()
        );
    }
}

// ---------------------------------------------------------------------------
// 6. Property-style: the returned plain Vec is ALWAYS sorted ascending by bytes
//    (the canonical invariant), for a range of cluster sizes and many shuffled
//    insert orders. This is the order-independent contract the fix establishes.
// ---------------------------------------------------------------------------

#[test]
fn returned_candidates_are_always_sorted_by_bytes() {
    // Deterministic LCG so the test is reproducible without an rng crate.
    let mut state: u64 = 0x9E3779B97F4A7C15;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as usize
    };

    for n in 2..=6usize {
        // Build n distinct equal-length values so glue ordering is unambiguous.
        let values: Vec<String> = (0..n).map(|i| format!("VAL{i:03}")).collect();
        for _ in 0..50 {
            // Fisher-Yates shuffle of indices 0..n.
            let mut idx: Vec<usize> = (0..n).collect();
            for i in (1..n).rev() {
                let j = next() % (i + 1);
                idx.swap(i, j);
            }

            let cache = FragmentCache::new(1024);
            let mut last: Vec<String> = Vec::new();
            for &k in &idx {
                // Lines 1..=n, all within 100 of each other -> every pair joins.
                last = cache
                    .record_and_reassemble(frag("p", "V", &values[k], "/p.py", k + 1))
                    .into_iter()
                    .map(|z| z.as_str().to_string())
                    .collect();
            }

            // n*(n-1) ordered pairs once the full cluster is present.
            assert_eq!(
                last.len(),
                n * (n - 1),
                "cluster of {n} near fragments => {} ordered joins",
                n * (n - 1)
            );

            // Canonical invariant: ascending by bytes.
            let mut sorted = last.clone();
            sorted.sort_unstable();
            assert_eq!(
                last, sorted,
                "returned candidates must already be byte-sorted (n={n}, order {idx:?})"
            );

            // And the set of glues must be exactly the expected ordered pairs.
            let mut expected: Vec<String> = Vec::new();
            for a in 0..n {
                for b in 0..n {
                    if a != b {
                        expected.push(format!("{}{}", values[a], values[b]));
                    }
                }
            }
            expected.sort_unstable();
            assert_eq!(
                last, expected,
                "byte-sorted glue set must match all ordered pairs (n={n})"
            );
        }
    }
}
