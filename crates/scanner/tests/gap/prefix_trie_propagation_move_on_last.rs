//! Regression: `collect_propagation` moves `descendant_indices` into the last
//! pattern slot at each trie node instead of cloning for every pattern (Law 7 —
//! the common single-pattern node now does zero clones), and the move changes no
//! output (Law 6).
//!
//! The propagation table answers "for prefix i, which prefixes are strict
//! superstrings of it?". Fixtures use linear chains (each node has one child) so
//! the descendant order is deterministic (no HashMap sibling-order ambiguity),
//! letting us pin the exact table. The duplicate-prefix fixture exercises the
//! clone-then-move path (a node with two patterns).

use keyhog_scanner::testing::build_propagation_table_for_test as build;

#[test]
fn linear_chain_propagation_is_exact_single_pattern_nodes() {
    // a -> ab -> abc : each node holds exactly one pattern, so the move-on-last
    // path runs with no clone.
    let table = build(&["a".to_string(), "ab".to_string(), "abc".to_string()]);
    assert_eq!(
        table,
        vec![
            vec![1, 2], // "a" is a prefix of "ab" and "abc"
            vec![2],    // "ab" is a prefix of "abc"
            vec![],     // "abc" has no superstring
        ],
        "each prefix lists exactly its strict superstrings, in chain order"
    );
}

#[test]
fn duplicate_prefix_node_clones_then_moves() {
    // "a" appears twice (one node, two pattern indices) with child "ab": indices
    // 0 and 1 both end at the 'a' node, so index 0 clones the descendants and
    // index 1 moves them — both must receive the same [2].
    let table = build(&["a".to_string(), "a".to_string(), "ab".to_string()]);
    assert_eq!(
        table,
        vec![
            vec![2], // first "a" (cloned descendants)
            vec![2], // second "a" (moved descendants) — identical
            vec![],  // "ab" has no superstring
        ],
        "duplicate-prefix patterns at one node both get the descendant set"
    );
}

#[test]
fn table_length_matches_input_and_disjoint_prefixes_have_no_superstrings() {
    // Disjoint prefixes: no superstring relationships, table is all-empty but
    // sized to the input.
    let table = build(&["foo".to_string(), "bar".to_string()]);
    assert_eq!(table, vec![Vec::<usize>::new(), Vec::<usize>::new()]);
    assert_eq!(table.len(), 2);
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors above pin the move-on-last output on hand-built chains; these
// SWEEP the propagation table against a naive O(N²) superstring oracle over
// generated prefix sets. This table is recall-load-bearing: it drives "a broad
// prefix hit cheaply activates its more-specific superstring detectors" in the
// phase-1 AC prefilter, so a MISSING superstring (incompleteness) silently fails
// to activate a detector = lost recall, and a SPURIOUS one wastes work. Sibling
// order is HashMap-nondeterministic, so every comparison is order-independent
// (both sides sorted). Driven only through the public
// `build_propagation_table_for_test` facade; no proptest covered this before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// SOUNDNESS + COMPLETENESS: `table[i]` must equal EXACTLY the set of indices
    /// `j` whose prefix is a strict superstring of `prefixes[i]` — i.e.
    /// `prefixes[j].starts_with(prefixes[i]) && prefixes[j].len() > prefixes[i].len()`.
    /// The small `[a-c]` alphabet with lengths 0..5 (empty strings included)
    /// densely generates shared prefixes, duplicates, and chains, so the trie's
    /// descendant-collection is checked against the ground-truth relation on rich
    /// overlap. Also pins the shape (one row per input) and irreflexivity
    /// (`i ∉ table[i]` — a prefix is never its own strict superstring).
    #[test]
    fn propagation_matches_naive_strict_superstring_relation(
        prefixes in prop::collection::vec("[a-c]{0,5}", 0..12),
    ) {
        let table = build(&prefixes);
        prop_assert_eq!(table.len(), prefixes.len());
        for (i, row) in table.iter().enumerate() {
            let mut expected: Vec<usize> = (0..prefixes.len())
                .filter(|&j| {
                    prefixes[j].starts_with(prefixes[i].as_str())
                        && prefixes[j].len() > prefixes[i].len()
                })
                .collect();
            let mut got = row.clone();
            expected.sort_unstable();
            got.sort_unstable();
            prop_assert_eq!(got, expected, "row {} mismatch for prefix {:?}", i, prefixes[i]);
            prop_assert!(!row.contains(&i), "row {} is self-referential", i);
        }
    }

    /// `build_propagation_table_for_test` must never panic on arbitrary prefixes
    /// — including empty strings, multi-byte Unicode, and embedded newlines
    /// (`(?s)`) — since the trie walks `.chars()` and indexes the output by input
    /// position. The table length must still equal the input length regardless of
    /// content.
    #[test]
    fn build_propagation_table_never_panics_on_arbitrary_unicode(
        prefixes in prop::collection::vec("(?s).{0,6}", 0..10),
    ) {
        let table = build(&prefixes);
        prop_assert_eq!(table.len(), prefixes.len());
    }
}
