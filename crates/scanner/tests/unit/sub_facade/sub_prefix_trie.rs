//! Standalone unit coverage for `keyhog_scanner::testing::build_propagation_table`.
//!
//! The propagation table maps each prefix to the set of OTHER prefixes that are
//! proper superstrings of it (children in the trie). These tests assert the
//! exact index sets, order-insensitive, for nested, sibling, duplicate, and
//! empty-prefix cases, never just `.len()`.

use keyhog_scanner::testing::build_propagation_table;

/// Sort a propagation row so set-equality assertions are order-insensitive.
fn sorted(mut v: Vec<usize>) -> Vec<usize> {
    v.sort_unstable();
    v
}

#[test]
fn shorter_prefix_propagates_to_its_superstring() {
    // "gh" (idx 0) is a prefix of "ghp_" (idx 1), so row 0 contains 1; "ghp_"
    // has no superstring among the set, so row 1 is empty.
    let table = build_propagation_table(&["gh".into(), "ghp_".into()]);
    assert_eq!(table.len(), 2);
    assert_eq!(sorted(table[0].clone()), vec![1]);
    assert!(table[1].is_empty());
}

#[test]
fn chained_prefixes_propagate_to_all_descendants() {
    // "g" < "gh" < "ghp_" : "g" propagates to BOTH deeper prefixes.
    let table = build_propagation_table(&["g".into(), "gh".into(), "ghp_".into()]);
    assert_eq!(sorted(table[0].clone()), vec![1, 2]); // g -> {gh, ghp_}
    assert_eq!(sorted(table[1].clone()), vec![2]); // gh -> {ghp_}
    assert!(table[2].is_empty()); // ghp_ -> {}
}

#[test]
fn siblings_do_not_propagate_to_each_other() {
    // "ghp_" and "ghs_" share the "gh" branch but neither is a prefix of the
    // other, so both rows are empty.
    let table = build_propagation_table(&["ghp_".into(), "ghs_".into()]);
    assert!(table[0].is_empty());
    assert!(table[1].is_empty());
}

#[test]
fn shared_root_propagates_to_both_branches() {
    // "gh" is a prefix of both "ghp_" (1) and "ghs_" (2).
    let table = build_propagation_table(&["gh".into(), "ghp_".into(), "ghs_".into()]);
    assert_eq!(sorted(table[0].clone()), vec![1, 2]);
    assert!(table[1].is_empty());
    assert!(table[2].is_empty());
}

#[test]
fn empty_prefix_propagates_to_everything_else() {
    // The empty prefix "" is a prefix of every other string in the set.
    let table = build_propagation_table(&["".into(), "a".into(), "ab".into()]);
    assert_eq!(sorted(table[0].clone()), vec![1, 2]); // "" -> {a, ab}
    assert_eq!(sorted(table[1].clone()), vec![2]); // "a" -> {ab}
    assert!(table[2].is_empty());
}

#[test]
fn unrelated_prefixes_are_isolated() {
    let table = build_propagation_table(&["aws".into(), "ghp_".into(), "npm_".into()]);
    assert_eq!(table.len(), 3);
    for row in &table {
        assert!(row.is_empty(), "unrelated prefixes must not propagate");
    }
}

#[test]
fn empty_input_yields_empty_table() {
    let table = build_propagation_table(&[]);
    assert!(table.is_empty());
}

#[test]
fn single_prefix_has_no_propagation() {
    let table = build_propagation_table(&["ghp_".into()]);
    assert_eq!(table.len(), 1);
    assert!(table[0].is_empty());
}

#[test]
fn duplicate_prefixes_each_get_the_descendant() {
    // Two identical "gh" entries (idx 0,1) and one "ghp_" (idx 2): both copies
    // of "gh" must list "ghp_" as a descendant. Identical-node siblings do not
    // list each other (descendants only, never the node's own pattern index).
    let table = build_propagation_table(&["gh".into(), "gh".into(), "ghp_".into()]);
    assert_eq!(sorted(table[0].clone()), vec![2]);
    assert_eq!(sorted(table[1].clone()), vec![2]);
    assert!(table[2].is_empty());
}

#[test]
fn multichar_unicode_prefix_propagates() {
    // Prefixes are walked by `char`, so a multibyte prefix still nests correctly.
    let table = build_propagation_table(&["café".into(), "caféX".into()]);
    assert_eq!(sorted(table[0].clone()), vec![1]);
    assert!(table[1].is_empty());
}
