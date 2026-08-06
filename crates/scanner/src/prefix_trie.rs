//! Prefix trie for efficient literal prefix extraction from detector regex patterns.
//!
//! Builds the prefix propagation table used by the Aho-Corasick prefilter in
//! phase 1 scanning so broad prefixes can cheaply activate more specific ones.

/// Prefix trie for O(n) propagation table construction.
///
/// Given N literal prefixes from detectors, we need to know:
/// "for prefix P, which other prefixes are superstrings of P?"
///
/// Naive: O(N²) - compare all pairs.
/// Trie: O(N * L) where L is average prefix length - insert all prefixes,
/// then for each prefix, all descendants in the trie are superstrings.
use std::collections::HashMap;

#[derive(Default)]
struct TrieNode {
    children: HashMap<char, TrieNode>,
    /// AC pattern indices that end at this node.
    pattern_indices: Vec<usize>,
}

/// Build a propagation table using a trie.
/// Returns: for each AC pattern index, a list of other pattern indices
/// whose prefix is a superstring.
/// Build a prefix propagation table for literal-prefix expansion.
///
/// # Examples
///
/// ```rust
/// use keyhog_scanner::testing::build_propagation_table_for_test;
///
/// let table = build_propagation_table_for_test(&["gh".into(), "ghp_".into()]);
/// assert_eq!(table.len(), 2);
/// ```
pub(crate) fn build_propagation_table(prefixes: &[String]) -> Vec<Vec<usize>> {
    let mut rows = vec![Vec::new(); prefixes.len()];
    for (row, value) in build_propagation_pairs(prefixes) {
        rows[row].push(value);
    }
    rows
}

pub(crate) fn build_propagation_pairs(prefixes: &[String]) -> Vec<(usize, usize)> {
    let root = build_trie(prefixes);
    let mut pairs = Vec::new();
    for (row, prefix) in prefixes.iter().enumerate() {
        let Some(node) = find_node(&root, prefix) else {
            continue;
        };
        for child in node.children.values() {
            collect_descendant_pairs(child, row, &mut pairs);
        }
    }
    pairs
}

fn build_trie(prefixes: &[String]) -> TrieNode {
    let mut root = TrieNode::default();
    for (index, prefix) in prefixes.iter().enumerate() {
        let mut node = &mut root;
        for character in prefix.chars() {
            node = node.children.entry(character).or_default();
        }
        node.pattern_indices.push(index);
    }
    root
}

fn find_node<'a>(root: &'a TrieNode, prefix: &str) -> Option<&'a TrieNode> {
    let mut node = root;
    for character in prefix.chars() {
        node = node.children.get(&character)?;
    }
    Some(node)
}

fn collect_descendant_pairs(node: &TrieNode, row: usize, pairs: &mut Vec<(usize, usize)>) {
    pairs.extend(
        node.pattern_indices
            .iter()
            .copied()
            .map(|value| (row, value)),
    );
    for child in node.children.values() {
        collect_descendant_pairs(child, row, pairs);
    }
}
