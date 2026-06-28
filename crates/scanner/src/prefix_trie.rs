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
/// use keyhog_scanner::testing::build_propagation_table;
///
/// let table = build_propagation_table(&["gh".into(), "ghp_".into()]);
/// assert_eq!(table.len(), 2);
/// ```
pub(crate) fn build_propagation_table(prefixes: &[String]) -> Vec<Vec<usize>> {
    let mut root = TrieNode::default();
    for (idx, prefix) in prefixes.iter().enumerate() {
        let mut node = &mut root;
        for ch in prefix.chars() {
            node = node.children.entry(ch).or_default();
        }
        node.pattern_indices.push(idx);
    }

    let mut propagation: Vec<Vec<usize>> = vec![Vec::new(); prefixes.len()];
    collect_propagation(&root, &mut propagation);
    propagation
}

fn collect_propagation(node: &TrieNode, propagation: &mut [Vec<usize>]) -> Vec<usize> {
    let mut subtree_indices = node.pattern_indices.clone();
    let mut descendant_indices = Vec::new();

    for child in node.children.values() {
        let child_subtree = collect_propagation(child, propagation);
        descendant_indices.extend_from_slice(&child_subtree);
        subtree_indices.extend_from_slice(&child_subtree);
    }

    // Each pattern ending at this node gets the descendant superstrings. The
    // last one moves `descendant_indices` (it is unused after this), so the
    // common single-pattern-per-node trie does zero clones here.
    if let Some((&last, rest)) = node.pattern_indices.split_last() {
        for &idx in rest {
            propagation[idx] = descendant_indices.clone();
        }
        propagation[last] = descendant_indices;
    }

    subtree_indices
}
