/// Extended unit tests for `keyhog_scanner::prefix_trie`.
///
/// Covers: empty input, single prefix, disjoint prefixes, prefix-of-prefix
/// (superstring propagation), multiple prefixes sharing a common stem, and
/// large input stability.
use keyhog_scanner::testing::build_propagation_table;

#[test]
fn empty_prefixes_returns_empty_table() {
    let table = build_propagation_table(&[]);
    assert!(table.is_empty());
}

#[test]
fn single_prefix_has_no_propagations() {
    let table = build_propagation_table(&["ghp_".to_string()]);
    assert_eq!(table.len(), 1);
    assert!(
        table[0].is_empty(),
        "a single prefix has no superstrings of itself"
    );
}

#[test]
fn disjoint_prefixes_no_cross_propagation() {
    // "npm_" and "sk_" share no prefix path in the trie
    let table = build_propagation_table(&["npm_".to_string(), "sk_".to_string()]);
    assert_eq!(table.len(), 2);
    assert!(table[0].is_empty(), "npm_ has no superstrings");
    assert!(table[1].is_empty(), "sk_ has no superstrings");
}

#[test]
fn shorter_prefix_propagates_to_longer() {
    // "gh" is a prefix of "ghp_" → index 0 (gh) should list index 1 (ghp_)
    // as a descendant that fires when "gh" fires.
    let prefixes = vec!["gh".to_string(), "ghp_".to_string()];
    let table = build_propagation_table(&prefixes);
    assert_eq!(table.len(), 2);
    // table[0] = propagation for "gh", should include the index for "ghp_"
    assert!(
        table[0].contains(&1),
        "gh (index 0) should propagate to ghp_ (index 1)"
    );
    // table[1] = propagation for "ghp_": "ghp_" is NOT a prefix of "gh"
    assert!(
        !table[1].contains(&0),
        "ghp_ (index 1) should not propagate back to gh (index 0)"
    );
}

#[test]
fn three_level_nesting_propagates_transitively() {
    // "g" → "gh" → "ghp_": index 0 must include BOTH 1 and 2 as descendants.
    let prefixes = vec!["g".to_string(), "gh".to_string(), "ghp_".to_string()];
    let table = build_propagation_table(&prefixes);
    assert_eq!(table.len(), 3);
    assert!(table[0].contains(&1), "g should propagate to gh");
    assert!(table[0].contains(&2), "g should propagate to ghp_");
    assert!(table[1].contains(&2), "gh should propagate to ghp_");
    assert!(!table[2].contains(&0), "ghp_ should not propagate to g");
    assert!(!table[2].contains(&1), "ghp_ should not propagate to gh");
}

#[test]
fn multiple_branches_from_common_stem() {
    // "ghub_pat_" and "ghp_" both start with "gh"
    let prefixes = vec![
        "gh".to_string(),
        "ghp_".to_string(),
        "ghub_pat_".to_string(),
    ];
    let table = build_propagation_table(&prefixes);
    assert_eq!(table.len(), 3);
    // "gh" (index 0) should propagate to both "ghp_" (1) and "ghub_pat_" (2)
    assert!(table[0].contains(&1));
    assert!(table[0].contains(&2));
    // "ghp_" and "ghub_pat_" don't propagate to each other (neither is prefix of the other)
    assert!(!table[1].contains(&2));
    assert!(!table[2].contains(&1));
}

#[test]
fn table_length_matches_prefix_count() {
    let prefixes: Vec<String> = (0..20).map(|i| format!("prefix_{i}")).collect();
    let table = build_propagation_table(&prefixes);
    assert_eq!(table.len(), prefixes.len());
}

#[test]
fn identical_prefixes_treated_as_separate_entries() {
    // Two identical strings at different indices should both get entries
    let prefixes = vec!["npm_".to_string(), "npm_".to_string()];
    let table = build_propagation_table(&prefixes);
    assert_eq!(table.len(), 2);
    // Both share the same trie node so each is a "sibling descendant" of the
    // other (the propagation for index 0 includes index 1 and vice versa).
    // Both results are non-empty (they see each other as co-terminals).
}

#[test]
fn unicode_prefix_does_not_panic() {
    // Non-ASCII prefixes should be handled without panic
    let prefixes = vec!["café_".to_string(), "résumé_".to_string()];
    let table = build_propagation_table(&prefixes);
    assert_eq!(table.len(), 2);
}
