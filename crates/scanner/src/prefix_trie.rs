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

#[derive(Default)]
struct TrieNode {
    /// `(character, node_index)` edges. Detector-prefix tries have tiny fanout
    /// at almost every node, so a flat row avoids one hash table per byte.
    children: Vec<(char, usize)>,
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
    let nodes = build_trie(prefixes);
    let mut pairs = Vec::new();
    for (row, prefix) in prefixes.iter().enumerate() {
        let Some(node_index) = find_node(&nodes, prefix) else {
            continue;
        };
        for &(_, child_index) in &nodes[node_index].children {
            collect_descendant_pairs(&nodes, child_index, row, &mut pairs);
        }
    }
    pairs
}

fn build_trie(prefixes: &[String]) -> Vec<TrieNode> {
    let mut nodes = vec![TrieNode::default()];
    for (pattern_index, prefix) in prefixes.iter().enumerate() {
        let mut node_index = 0;
        for character in prefix.chars() {
            let child_index = nodes[node_index]
                .children
                .iter()
                .find_map(|&(candidate, index)| (candidate == character).then_some(index));
            node_index = match child_index {
                Some(index) => index,
                None => {
                    let index = nodes.len();
                    nodes.push(TrieNode::default());
                    nodes[node_index].children.push((character, index));
                    index
                }
            };
        }
        nodes[node_index].pattern_indices.push(pattern_index);
    }
    nodes
}

fn find_node(nodes: &[TrieNode], prefix: &str) -> Option<usize> {
    let mut node_index = 0;
    for character in prefix.chars() {
        node_index = nodes[node_index]
            .children
            .iter()
            .find_map(|&(candidate, index)| (candidate == character).then_some(index))?;
    }
    Some(node_index)
}

fn collect_descendant_pairs(
    nodes: &[TrieNode],
    node_index: usize,
    row: usize,
    pairs: &mut Vec<(usize, usize)>,
) {
    pairs.extend(
        nodes[node_index]
            .pattern_indices
            .iter()
            .copied()
            .map(|value| (row, value)),
    );
    for &(_, child_index) in &nodes[node_index].children {
        collect_descendant_pairs(nodes, child_index, row, pairs);
    }
}
