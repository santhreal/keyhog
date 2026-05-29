//! Transitive reachability over an edge list  -  CPU reference + Tier-2.5
//! GPU Program builder.
//!
//! Consumed by taint analysis (`flows_to`) and graph analyses
//! that need "is B reachable from A given these edges?"
//!
//! AUDIT_2026-04-24 F-REACH-02 (RESOLVED): `reachable_program` now
//! ships as a Tier-2.5 builder. It fuses `csr_forward_traverse` +
//! `bitset_or` for up to `max_iters` steps in a single dispatch,
//! accumulating every discovered frontier into `reach_out`. The CPU
//! reference (`reachable`) is retained for the conform harness
//! cpu↔gpu bytecompare oracle.

use std::collections::HashSet;

use vyre_foundation::execution_plan::fusion::fuse_programs;
use vyre_foundation::ir::{DataType, Program};

use crate::bitset::bitset_words;
use crate::bitset::or::bitset_or;
use crate::graph::csr_forward_traverse::csr_forward_traverse;
use crate::graph::program_graph::ProgramGraphShape;

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::graph::reachable_program";

/// Error returned by [`reachable`] when the edge list contains a
/// node index outside `0..node_count`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownNode {
    /// Index into `edges` of the offending pair.
    pub index: usize,
    /// The out-of-range node id.
    pub node: u32,
    /// Total node count the graph was constructed with.
    pub node_count: u32,
}

impl std::fmt::Display for UnknownNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "reachable: edges[{}] references node {} but node_count = {}. \
             Fix: callers must deduplicate and bounds-check edges before \
             calling this primitive.",
            self.index, self.node, self.node_count
        )
    }
}

impl std::error::Error for UnknownNode {}

/// Error returned by [`try_reachable`] for malformed graph input or allocation
/// failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachableError {
    /// The edge list referenced a node outside `0..node_count`.
    UnknownNode(UnknownNode),
    /// Scratch allocation failed before traversal could complete.
    Allocation(String),
}

impl std::fmt::Display for ReachableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownNode(error) => error.fmt(f),
            Self::Allocation(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ReachableError {}

impl From<UnknownNode> for ReachableError {
    fn from(error: UnknownNode) -> Self {
        Self::UnknownNode(error)
    }
}

/// CPU reference: returns the set of nodes reachable from any element
/// of `sources` following the directed edges. `edges` is a slice of
/// `(from, to)` u32 pairs  -  a BFS/DFS walks `from → to`.
///
/// AUDIT_2026-04-24 F-REACH-01: prior version silently dropped
/// edges whose `from` or `to` exceeded `node_count`, masking
/// upstream bugs that produce malformed edge lists. Now returns
/// [`UnknownNode`] so the violation is visible at the call site  -
/// consistent with how `toposort` surfaces the same shape of
/// failure.
pub fn reachable(
    node_count: u32,
    edges: &[(u32, u32)],
    sources: &[u32],
) -> Result<HashSet<u32>, UnknownNode> {
    match try_reachable(node_count, edges, sources) {
        Ok(result) => Ok(result),
        Err(ReachableError::UnknownNode(error)) => Err(error),
        Err(ReachableError::Allocation(message)) => {
            panic!("reachable CPU oracle allocation failed. {message}")
        }
    }
}

/// Fallible CPU reference for transitive reachability.
///
/// Unlike [`reachable`], this surfaces allocation failure as a typed error, so
/// hostile graph dimensions cannot abort the process through infallible vector
/// growth.
pub fn try_reachable(
    node_count: u32,
    edges: &[(u32, u32)],
    sources: &[u32],
) -> Result<HashSet<u32>, ReachableError> {
    const NONE: usize = usize::MAX;

    let n = node_count as usize;
    for (index, &(from, to)) in edges.iter().enumerate() {
        if (from as usize) >= n {
            return Err(ReachableError::UnknownNode(UnknownNode {
                index,
                node: from,
                node_count,
            }));
        }
        if (to as usize) >= n {
            return Err(ReachableError::UnknownNode(UnknownNode {
                index,
                node: to,
                node_count,
            }));
        }
    }
    let mut head: Vec<usize> = Vec::new();
    crate::graph::scratch::reserve_graph_items(
        &mut head,
        n,
        "reachable CPU oracle",
        "adjacency heads",
    )
    .map_err(ReachableError::Allocation)?;
    head.resize(n, NONE);
    let mut to_nodes: Vec<u32> = Vec::new();
    crate::graph::scratch::reserve_graph_items(
        &mut to_nodes,
        edges.len(),
        "reachable CPU oracle",
        "adjacency destinations",
    )
    .map_err(ReachableError::Allocation)?;
    let mut next_edges: Vec<usize> = Vec::new();
    crate::graph::scratch::reserve_graph_items(
        &mut next_edges,
        edges.len(),
        "reachable CPU oracle",
        "adjacency next links",
    )
    .map_err(ReachableError::Allocation)?;
    for &(from, to) in edges {
        let edge_index = to_nodes.len();
        to_nodes.push(to);
        next_edges.push(head[from as usize]);
        head[from as usize] = edge_index;
    }
    let mut visited: Vec<bool> = Vec::new();
    crate::graph::scratch::reserve_graph_items(
        &mut visited,
        n,
        "reachable CPU oracle",
        "visited bitmap",
    )
    .map_err(ReachableError::Allocation)?;
    visited.resize(n, false);
    let mut out_of_range_sources: Vec<u32> = Vec::new();
    crate::graph::scratch::reserve_graph_items(
        &mut out_of_range_sources,
        sources.len(),
        "reachable CPU oracle",
        "out-of-range source list",
    )
    .map_err(ReachableError::Allocation)?;
    let mut stack: Vec<u32> = Vec::new();
    crate::graph::scratch::reserve_graph_items(
        &mut stack,
        sources.len(),
        "reachable CPU oracle",
        "DFS stack",
    )
    .map_err(ReachableError::Allocation)?;
    stack.extend_from_slice(sources);
    while let Some(v) = stack.pop() {
        let idx = v as usize;
        if idx >= n {
            out_of_range_sources.push(v);
            continue;
        }
        if visited[idx] {
            continue;
        }
        visited[idx] = true;
        let mut edge = head[idx];
        while edge != NONE {
            let next = to_nodes[edge];
            if !visited[next as usize] {
                stack.push(next);
            }
            edge = next_edges[edge];
        }
    }
    let result_capacity = visited
        .iter()
        .filter(|&&is_visited| is_visited)
        .count()
        .saturating_add(out_of_range_sources.len());
    let mut result = HashSet::new();
    result.try_reserve(result_capacity).map_err(|error| {
        ReachableError::Allocation(format!(
            "Fix: reachable CPU oracle could not reserve {result_capacity} result nodes: {error}"
        ))
    })?;
    for (idx, is_visited) in visited.into_iter().enumerate() {
        if is_visited {
            result.insert(idx as u32);
        }
    }
    result.extend(out_of_range_sources);
    Ok(result)
}

/// Build a Tier-2.5 GPU Program for transitive reachability.
///
/// The returned Program performs up to `max_iters` forward-traversal
/// steps over the CSR graph described by `shape`, starting from the
/// packed bitset `sources_buf`, and accumulates the union of every
/// visited frontier into `reach_out`.
///
/// # Composition
///
/// 1. Seed `reach_out` with `sources_buf` via `bitset_or`.
/// 2. For each iteration `0..max_iters`:
///    - `csr_forward_traverse` from the current frontier into a
///      ping-pong scratch buffer (`reach_frontier_a` / `reach_frontier_b`).
///    - `bitset_or` the new frontier into `reach_out`.
///
/// All arms are fused into a single dispatch via `fuse_programs`.
///
/// # Caller contract
///
/// * Bind the canonical five-buffer ProgramGraph CSR
///   (`pg_nodes`, `pg_edge_offsets`, `pg_edge_targets`,
///   `pg_edge_kind_mask`, `pg_node_tags`) before dispatch.
/// * Zero-initialise `reach_out`, `reach_frontier_a`, and
///   `reach_frontier_b` before the first dispatch.
/// * `sources_buf` must be a packed bitset with `bitset_words(node_count)`
///   u32 words.
/// * `node_count` must be `> 0` (zero-node graphs are not supported
///   by the underlying bitset primitives).
///
/// # Panics
///
/// Panics if `fuse_programs` detects an unexpected hazard. This
/// builder constructs a known-safe composition, so a panic indicates
/// an internal invariant violation, not a caller error.
#[must_use]
pub fn reachable_program(
    node_count: u32,
    edge_count: u32,
    sources_buf: &str,
    reach_out: &str,
    max_iters: u32,
) -> Program {
    let shape = ProgramGraphShape::new(node_count, edge_count);
    let words = bitset_words(node_count);
    let frontier_a = "reach_frontier_a";
    let frontier_b = "reach_frontier_b";

    let Some(iter_arms) = (max_iters as usize).checked_mul(2) else {
        return crate::invalid_output_program(
            OP_ID,
            reach_out,
            DataType::U32,
            "Fix: reachable_program max_iters*2 overflows usize.".to_string(),
        );
    };
    let Some(arm_count) = iter_arms.checked_add(1) else {
        return crate::invalid_output_program(
            OP_ID,
            reach_out,
            DataType::U32,
            "Fix: reachable_program arm count overflows usize.".to_string(),
        );
    };
    let mut arms: Vec<Program> = Vec::new();
    if let Err(error) = arms.try_reserve(arm_count) {
        return crate::invalid_output_program(
            OP_ID,
            reach_out,
            DataType::U32,
            format!("Fix: reachable_program could not reserve {arm_count} fused arms: {error}"),
        );
    }

    // Seed reach_out with the initial sources so the final result
    // includes the source set itself.
    arms.push(bitset_or(sources_buf, reach_out, reach_out, words));

    for i in 0..max_iters {
        let in_buf = if i == 0 {
            sources_buf
        } else if i % 2 == 1 {
            frontier_a
        } else {
            frontier_b
        };
        let out_buf = if i % 2 == 0 { frontier_a } else { frontier_b };

        arms.push(csr_forward_traverse(shape, in_buf, out_buf, u32::MAX));
        arms.push(bitset_or(out_buf, reach_out, reach_out, words));
    }

    fuse_programs(&arms).unwrap_or_else(|error| {
        crate::invalid_output_program(
            OP_ID,
            reach_out,
            DataType::U32,
            format!("Fix: reachable_program composition failed: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hs(items: &[u32]) -> HashSet<u32> {
        items.iter().copied().collect()
    }

    #[test]
    fn generated_try_reachable_matches_legacy_reachable() {
        for node_count in 1u32..=64 {
            for seed in 0u32..64 {
                let edges: Vec<(u32, u32)> = (0..node_count)
                    .filter_map(|node| {
                        let step = (seed % 7) + 1;
                        let dst = node.saturating_add(step);
                        (dst < node_count).then_some((node, dst))
                    })
                    .collect();
                let sources = [seed % node_count, node_count + seed];
                let fallible = try_reachable(node_count, &edges, &sources).unwrap();
                let legacy = reachable(node_count, &edges, &sources).unwrap();
                assert_eq!(fallible, legacy);
                assert!(fallible.contains(&(node_count + seed)));
            }
        }
    }

    #[test]
    fn empty_sources_reach_nothing() {
        let got = reachable(3, &[(0, 1), (1, 2)], &[]).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn single_source_reaches_chain() {
        let got = reachable(3, &[(0, 1), (1, 2)], &[0]).unwrap();
        assert_eq!(got, hs(&[0, 1, 2]));
    }

    #[test]
    fn cycle_terminates() {
        // 0 → 1 → 0 (cycle). Starting from 0 should still terminate.
        let got = reachable(2, &[(0, 1), (1, 0)], &[0]).unwrap();
        assert_eq!(got, hs(&[0, 1]));
    }

    #[test]
    fn disconnected_source_not_included() {
        let got = reachable(4, &[(0, 1), (2, 3)], &[0]).unwrap();
        assert_eq!(got, hs(&[0, 1]));
        assert!(!got.contains(&2));
        assert!(!got.contains(&3));
    }

    #[test]
    fn unknown_source_is_noop() {
        // Source node 7 doesn't exist in a 2-node graph; reachable
        // should return just {7} (source is trivially reachable from
        // itself) without panicking.
        let got = reachable(2, &[(0, 1)], &[7]).unwrap();
        assert_eq!(got, hs(&[7]));
    }

    #[test]
    fn out_of_range_edge_is_reported_not_silently_dropped() {
        // AUDIT_2026-04-24 F-REACH-01: prior code silently dropped
        // the (5, 1) edge. Now it surfaces UnknownNode.
        let err = reachable(3, &[(0, 1), (5, 1)], &[0]).unwrap_err();
        assert_eq!(err.index, 1);
        assert_eq!(err.node, 5);
        assert_eq!(err.node_count, 3);
    }

    #[test]
    fn reachable_program_smoke() {
        // AUDIT_2026-04-24 F-REACH-02: smoke test that the Tier-2.5
        // builder produces a valid, non-empty fused Program.
        let program = reachable_program(4, 4, "sources", "reach", 2);
        assert!(!program.is_explicit_noop());
        assert!(!program.buffers().is_empty());
        assert!(!program.entry().is_empty());

        // The fused program should declare the canonical CSR buffers,
        // the caller-provided bitsets, and the two ping-pong scratch
        // buffers.
        let names: Vec<&str> = program.buffers().iter().map(|b| b.name()).collect();
        assert!(names.contains(&"pg_edge_offsets"));
        assert!(names.contains(&"pg_edge_targets"));
        assert!(names.contains(&"sources"));
        assert!(names.contains(&"reach"));
        assert!(names.contains(&"reach_frontier_a"));
        assert!(names.contains(&"reach_frontier_b"));
    }

    #[test]
    fn reachable_program_zero_iters_seeds_only() {
        // With max_iters = 0 the program should still contain the
        // preliminary seed step (sources | reach_out -> reach_out).
        let program = reachable_program(4, 4, "sources", "reach", 0);
        assert!(!program.is_explicit_noop());
        assert!(!program.buffers().is_empty());
    }
}
