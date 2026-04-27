//! Transitive reachability over an edge list — CPU reference + Tier-2.5
//! GPU Program builder.
//!
//! Consumed by surgec `flows_to` taint analysis and any future
//! analysis that needs "is B reachable from A given these edges?"
//!
//! AUDIT_2026-04-24 F-REACH-02 (RESOLVED): `reachable_program` now
//! ships as a Tier-2.5 builder. It fuses `csr_forward_traverse` +
//! `bitset_or` for up to `max_iters` steps in a single dispatch,
//! accumulating every discovered frontier into `reach_out`. The CPU
//! reference (`reachable`) is retained for the conform harness
//! cpu↔gpu bytecompare oracle.

use std::collections::HashSet;

use vyre_foundation::execution_plan::fusion::fuse_programs;
use vyre_foundation::ir::Program;

use crate::bitset::bitset_words;
use crate::bitset::or::bitset_or;
use crate::graph::csr_forward_traverse::csr_forward_traverse;
use crate::graph::program_graph::ProgramGraphShape;

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

/// CPU reference: returns the set of nodes reachable from any element
/// of `sources` following the directed edges. `edges` is a slice of
/// `(from, to)` u32 pairs — a BFS/DFS walks `from → to`.
///
/// AUDIT_2026-04-24 F-REACH-01: prior version silently dropped
/// edges whose `from` or `to` exceeded `node_count`, masking
/// upstream bugs that produce malformed edge lists. Now returns
/// [`UnknownNode`] so the violation is visible at the call site —
/// consistent with how `toposort` surfaces the same shape of
/// failure.
pub fn reachable(
    node_count: u32,
    edges: &[(u32, u32)],
    sources: &[u32],
) -> Result<HashSet<u32>, UnknownNode> {
    let n = node_count as usize;
    let mut adj: Vec<Vec<u32>> = vec![Vec::new(); n];
    for (index, &(from, to)) in edges.iter().enumerate() {
        if (from as usize) >= n {
            return Err(UnknownNode {
                index,
                node: from,
                node_count,
            });
        }
        if (to as usize) >= n {
            return Err(UnknownNode {
                index,
                node: to,
                node_count,
            });
        }
        adj[from as usize].push(to);
    }
    let mut visited: HashSet<u32> = HashSet::with_capacity(n);
    let mut stack: Vec<u32> = sources.to_vec();
    while let Some(v) = stack.pop() {
        if !visited.insert(v) {
            continue;
        }
        if (v as usize) < n {
            for &u in &adj[v as usize] {
                if !visited.contains(&u) {
                    stack.push(u);
                }
            }
        }
    }
    Ok(visited)
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

    let mut arms: Vec<Program> =
        Vec::with_capacity((max_iters as usize).saturating_mul(2).saturating_add(1));

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

    fuse_programs(&arms)
        .expect("reachable_program: fuse_programs should not fail for this composition")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hs(items: &[u32]) -> HashSet<u32> {
        items.iter().copied().collect()
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
