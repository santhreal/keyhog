use keyhog_scanner::prefix_trie::build_propagation_table;

#[test]
fn basic_propagation() {
    let prefixes = vec![
        "sk-".to_string(),      // 0
        "sk-proj-".to_string(), // 1
        "sk-ant-".to_string(),  // 2
        "ghp_".to_string(),     // 3
    ];
    let table = build_propagation_table(&prefixes);

    // "sk-" should propagate to "sk-proj-" and "sk-ant-"
    assert!(table[0].contains(&1));
    assert!(table[0].contains(&2));
    assert!(!table[0].contains(&3)); // ghp_ is not a superstring of sk-

    // "sk-proj-" should not propagate to anything (nothing starts with "sk-proj-X")
    assert!(table[1].is_empty());

    // "ghp_" should not propagate to anything
    assert!(table[3].is_empty());
}

#[test]
fn no_self_propagation() {
    let prefixes = vec!["abc".to_string(), "abcd".to_string()];
    let table = build_propagation_table(&prefixes);

    // "abc" propagates to "abcd" but not to itself
    assert_eq!(table[0], vec![1]);
    assert!(!table[0].contains(&0));
}

#[test]
fn deep_chain() {
    let prefixes = vec![
        "a".to_string(),    // 0
        "ab".to_string(),   // 1
        "abc".to_string(),  // 2
        "abcd".to_string(), // 3
    ];
    let table = build_propagation_table(&prefixes);

    // "a" should propagate to all others
    assert_eq!(table[0].len(), 3);
    // "abc" should propagate to "abcd"
    assert_eq!(table[2], vec![3]);
    // "abcd" propagates to nothing
    assert!(table[3].is_empty());
}

#[test]
fn empty_input() {
    let table = build_propagation_table(&[]);
    assert!(table.is_empty());
}
