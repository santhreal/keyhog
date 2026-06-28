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
