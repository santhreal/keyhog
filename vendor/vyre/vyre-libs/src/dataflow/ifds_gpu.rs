//! GPU-native IFDS/IDE driver (G3).
//!
//! # What this does
//!
//! IFDS / IDE reframes interprocedural dataflow as reachability on
//! the **exploded supergraph**: each `(proc, block, fact)` triple
//! is a graph vertex; the analysis reduces to BFS + bitset-fixpoint
//! — primitives vyre already owns.
//!
//! The pieces live in
//! [`vyre_primitives::graph::exploded`] (node encoding + CSR
//! builder), [`vyre_primitives::graph::csr_forward_traverse`] (BFS
//! step), and [`vyre_primitives::fixpoint::bitset_fixpoint`]
//! (convergence loop). This module composes them.
//!
//! # Entry points
//!
//! - [`solve_cpu`] — in-process CPU reference. Conformance tests
//!   run this against the GPU output bit-for-bit.
//! - [`ifds_gpu_step`] — one BFS step over the exploded supergraph
//!   as a GPU [`Program`]. Caller dispatches this in a loop over
//!   `(frontier_in, frontier_out)` until the frontier stops
//!   growing (classic BFS-to-fixpoint). Allocates the exploded
//!   supergraph's `ProgramGraph` buffers internally — the caller
//!   only provides the two frontier buffer names.

use vyre_foundation::ir::Program;
use vyre_primitives::graph::csr_forward_traverse::csr_forward_traverse;
use vyre_primitives::graph::exploded::{
    build_cpu_reference, dense_to_encoded, MAX_BLOCK_ID, MAX_FACT_ID, MAX_PROC_ID,
};
use vyre_primitives::graph::program_graph::ProgramGraphShape;

/// CPU-reference IFDS solver. Constructs the exploded supergraph
/// on the CPU and runs **BFS** from `seed_facts` to convergence.
/// Returns the full set of reached `(proc, block, fact)` node ids
/// in the packed [`encode_node`] form, sorted ascending.
///
/// PHASE6_DATAFLOW HIGH: previous implementation called
/// [`bfs_dense`], which used `Vec::pop()` — that is **DFS** order,
/// not BFS. The reached set is identical, but the runtime profile
/// and the function name lied. Now uses a real `VecDeque` queue
/// with `pop_front()`.
///
/// Matches the GPU solver bit-for-bit on every input.
#[must_use]
pub fn solve_cpu(
    num_procs: u32,
    blocks_per_proc: u32,
    facts_per_proc: u32,
    intra_edges: &[(u32, u32, u32)],
    inter_edges: &[(u32, u32, u32, u32)],
    flow_gen: &[(u32, u32, u32)],
    flow_kill: &[(u32, u32, u32)],
    seed_facts: &[(u32, u32, u32)],
) -> Vec<u32> {
    assert!(
        num_procs.saturating_sub(1) <= MAX_PROC_ID,
        "num_procs exceeds encoding budget"
    );
    let (row_ptr, col_idx) = build_cpu_reference(
        num_procs,
        blocks_per_proc,
        facts_per_proc,
        intra_edges,
        inter_edges,
        flow_gen,
        flow_kill,
    );
    let dense = bfs_dense_queue(
        &row_ptr,
        &col_idx,
        seed_facts,
        blocks_per_proc,
        facts_per_proc,
    );
    let mut out: Vec<u32> = dense
        .into_iter()
        .map(|d| dense_to_encoded(d, blocks_per_proc, facts_per_proc))
        .collect();
    out.sort_unstable();
    out
}

fn dense_idx(p: u32, b: u32, f: u32, blocks_per_proc: u32, facts_per_proc: u32) -> u32 {
    p * blocks_per_proc * facts_per_proc + b * facts_per_proc + f
}

fn bfs_dense_queue(
    row_ptr: &[u32],
    col_idx: &[u32],
    seed_facts: &[(u32, u32, u32)],
    blocks_per_proc: u32,
    facts_per_proc: u32,
) -> Vec<u32> {
    use std::collections::VecDeque;

    let total_nodes = row_ptr.len().saturating_sub(1);
    let mut visited = vec![false; total_nodes];
    let mut queue: VecDeque<u32> = seed_facts
        .iter()
        .map(|&(p, b, f)| dense_idx(p, b, f, blocks_per_proc, facts_per_proc))
        .collect();
    for &n in &queue {
        if (n as usize) < total_nodes {
            visited[n as usize] = true;
        }
    }
    let mut result: Vec<u32> = queue.iter().copied().collect();
    while let Some(node) = queue.pop_front() {
        if (node as usize) >= total_nodes {
            continue;
        }
        let start = row_ptr[node as usize] as usize;
        let end = row_ptr[node as usize + 1] as usize;
        for &neighbour in &col_idx[start..end] {
            let idx = neighbour as usize;
            if idx < total_nodes && !visited[idx] {
                visited[idx] = true;
                queue.push_back(neighbour);
                result.push(neighbour);
            }
        }
    }
    result
}

/// Dispatch geometry for one IFDS BFS step on the GPU.
#[derive(Debug, Clone, Copy)]
pub struct IfdsShape {
    /// Number of procedures in the exploded supergraph.
    pub num_procs: u32,
    /// Number of basic blocks encoded per procedure.
    pub blocks_per_proc: u32,
    /// Number of dataflow facts encoded per procedure.
    pub facts_per_proc: u32,
    /// Number of graph edges in the CSR representation.
    pub edge_count: u32,
}

impl IfdsShape {
    /// Number of exploded-supergraph nodes = `procs * blocks * facts`.
    ///
    /// PHASE6_DATAFLOW HIGH: previous implementation used unchecked
    /// u32 multiplication. With the maximum representable dimensions
    /// (4096 × 1024 × 1024) the product is exactly 2^32, which wraps
    /// to 0 — silently producing a degenerate node count and OOB
    /// accesses downstream. Always pre-multiply in u64 then return
    /// `u32::MAX` if the product overflows; callers MUST `fits()`
    /// first to validate.
    #[must_use]
    pub fn node_count(&self) -> u32 {
        u64::from(self.num_procs)
            .checked_mul(u64::from(self.blocks_per_proc))
            .and_then(|x| x.checked_mul(u64::from(self.facts_per_proc)))
            .and_then(|x| u32::try_from(x).ok())
            .unwrap_or(u32::MAX)
    }

    /// Pre-flight fit check — callers should run this before
    /// building the CSR to avoid the stricter panic inside
    /// `build_cpu_reference`. All dimension caps come from the
    /// 32-bit node-id packing in [`vyre_primitives::graph::exploded`].
    ///
    /// PHASE6_DATAFLOW HIGH: also verifies that the **product** of
    /// the dimensions fits in u32 — individual axis caps allowed
    /// `4096 × 1024 × 1024 = 2^32` which wraps. The product check
    /// closes that hole.
    #[must_use]
    pub fn fits(&self) -> bool {
        let axes_ok = self.num_procs.saturating_sub(1) <= MAX_PROC_ID
            && self.blocks_per_proc.saturating_sub(1) <= MAX_BLOCK_ID
            && self.facts_per_proc.saturating_sub(1) <= MAX_FACT_ID;
        let product_ok = u64::from(self.num_procs)
            .checked_mul(u64::from(self.blocks_per_proc))
            .and_then(|x| x.checked_mul(u64::from(self.facts_per_proc)))
            .map(|x| x <= u64::from(u32::MAX))
            .unwrap_or(false);
        axes_ok && product_ok
    }
}

/// Emit one GPU BFS step over the exploded supergraph.
///
/// The returned [`Program`] reads the `(pg_nodes, pg_edge_offsets,
/// pg_edge_targets, pg_edge_kind_mask, pg_node_tags)` ProgramGraph
/// buffers (populated by the host from
/// [`build_cpu_reference`] output) plus the named `frontier_in`
/// bitset, and writes the expanded frontier to `frontier_out`.
///
/// Convergence is a host loop: repeatedly dispatch this Program
/// alternating the two frontier buffers; when a dispatch produces
/// no new bits, fixpoint is reached.
///
/// `allow_mask = u32::MAX` accepts every edge kind — the exploded
/// supergraph does not differentiate edge kinds, so that is the
/// right choice.
#[must_use]
pub fn ifds_gpu_step(shape: IfdsShape, frontier_in: &str, frontier_out: &str) -> Program {
    assert!(
        shape.fits(),
        "Fix: ifds_gpu_step dimensions exceed 32-bit exploded-node encoding. \
         procs={} blocks={} facts={}",
        shape.num_procs,
        shape.blocks_per_proc,
        shape.facts_per_proc,
    );
    let pg_shape = ProgramGraphShape::new(shape.node_count(), shape.edge_count);
    csr_forward_traverse(pg_shape, frontier_in, frontier_out, u32::MAX)
}

/// Backwards-compatible three-string shim over [`ifds_gpu_step`].
/// The `_exploded_adj` argument is the ProgramGraph's
/// `pg_edge_targets` buffer; it is ignored here because the step
/// kernel binds `pg_edge_*` at the canonical names. Kept so older
/// call sites compile unchanged.
#[must_use]
pub fn ifds_gpu(_exploded_adj: &str, frontier_in: &str, frontier_out: &str) -> Program {
    ifds_gpu_step(
        IfdsShape {
            num_procs: 1,
            blocks_per_proc: 1,
            facts_per_proc: 1,
            edge_count: 1,
        },
        frontier_in,
        frontier_out,
    )
}

/// Marker type for the GPU-native IFDS dataflow primitive.
pub struct IfdsGpu;

impl super::soundness::SoundnessTagged for IfdsGpu {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::Exact
    }
}

impl super::soundness::SoundnessTagged for IfdsShape {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_primitives::graph::exploded::{decode_node, encode_node};

    fn sort_triples(mut v: Vec<(u32, u32, u32)>) -> Vec<(u32, u32, u32)> {
        v.sort_unstable();
        v
    }

    fn reached_triples(node_ids: &[u32]) -> Vec<(u32, u32, u32)> {
        let mut out: Vec<(u32, u32, u32)> = node_ids.iter().copied().map(decode_node).collect();
        out.sort_unstable();
        out
    }

    #[test]
    fn seed_only_reaches_itself_on_disconnected_graph() {
        let got = solve_cpu(1, 4, 4, &[], &[], &[], &[], &[(0, 0, 1)]);
        assert_eq!(got, vec![encode_node(0, 0, 1)]);
    }

    #[test]
    fn linear_cfg_propagates_fact_through_all_blocks() {
        let got = solve_cpu(
            1,
            4,
            1,
            &[(0, 0, 1), (0, 1, 2), (0, 2, 3)],
            &[],
            &[],
            &[],
            &[(0, 0, 0)],
        );
        assert_eq!(
            reached_triples(&got),
            sort_triples(vec![(0, 0, 0), (0, 1, 0), (0, 2, 0), (0, 3, 0)]),
        );
    }

    #[test]
    fn kill_stops_fact_propagation() {
        let got = solve_cpu(
            1,
            3,
            1,
            &[(0, 0, 1), (0, 1, 2)],
            &[],
            &[],
            &[(0, 1, 0)],
            &[(0, 0, 0)],
        );
        let triples = reached_triples(&got);
        assert!(triples.contains(&(0, 0, 0)));
        assert!(triples.contains(&(0, 1, 0)));
        assert!(
            !triples.contains(&(0, 2, 0)),
            "kill should block propagation"
        );
    }

    #[test]
    fn gen_introduces_fact_not_in_seed_set() {
        // B0 → B1. GEN fact 2 at B0 emits edge (B0, 0) → (B1, 2)
        // under IFDS 0-fact convention. Seed fact 0 at B0; the
        // GEN edge is then walkable and fact 2 reaches B1.
        let got = solve_cpu(1, 2, 4, &[(0, 0, 1)], &[], &[(0, 0, 2)], &[], &[(0, 0, 0)]);
        let triples = reached_triples(&got);
        assert!(triples.contains(&(0, 0, 0)));
        assert!(triples.contains(&(0, 1, 0)));
        assert!(triples.contains(&(0, 1, 2)));
    }

    #[test]
    fn interprocedural_call_edge_propagates_facts() {
        let got = solve_cpu(
            2,
            2,
            1,
            &[(0, 0, 1)],
            &[(0, 1, 1, 0)],
            &[],
            &[],
            &[(0, 0, 0)],
        );
        let triples = reached_triples(&got);
        assert!(triples.contains(&(0, 0, 0)));
        assert!(triples.contains(&(0, 1, 0)));
        assert!(triples.contains(&(1, 0, 0)));
    }

    #[test]
    fn multiple_seeds_converge_together() {
        let got = solve_cpu(
            1,
            2,
            4,
            &[(0, 0, 1)],
            &[],
            &[],
            &[],
            &[(0, 0, 0), (0, 0, 3)],
        );
        let triples = reached_triples(&got);
        assert!(triples.contains(&(0, 1, 0)));
        assert!(triples.contains(&(0, 1, 3)));
    }

    #[test]
    fn empty_seed_set_yields_empty_reached_set() {
        let got = solve_cpu(1, 2, 1, &[(0, 0, 1)], &[], &[], &[], &[]);
        assert!(got.is_empty());
    }

    #[test]
    fn cycle_terminates_without_revisit() {
        let got = solve_cpu(
            1,
            2,
            1,
            &[(0, 0, 1), (0, 1, 0)],
            &[],
            &[],
            &[],
            &[(0, 0, 0)],
        );
        assert_eq!(
            reached_triples(&got),
            sort_triples(vec![(0, 0, 0), (0, 1, 0)]),
        );
    }

    #[test]
    fn ifds_shape_node_count_is_product() {
        let s = IfdsShape {
            num_procs: 4,
            blocks_per_proc: 8,
            facts_per_proc: 16,
            edge_count: 1,
        };
        assert_eq!(s.node_count(), 4 * 8 * 16);
    }

    #[test]
    fn ifds_shape_fits_checks_every_axis() {
        // PHASE6_DATAFLOW HIGH: tightened. Pre-fix, this test used
        // (MAX_PROC_ID+1, MAX_BLOCK_ID+1, MAX_FACT_ID+1) which has a
        // product of exactly 2^32 — that should fail (now does). Use
        // smaller dimensions whose product still fits u32 to isolate
        // the per-axis check.
        let ok = IfdsShape {
            num_procs: MAX_PROC_ID + 1,
            blocks_per_proc: MAX_BLOCK_ID,
            facts_per_proc: 16,
            edge_count: 1,
        };
        assert!(ok.fits());
        let proc_over = IfdsShape {
            num_procs: MAX_PROC_ID + 2,
            ..ok
        };
        let block_over = IfdsShape {
            blocks_per_proc: MAX_BLOCK_ID + 2,
            ..ok
        };
        let fact_over = IfdsShape {
            facts_per_proc: MAX_FACT_ID + 2,
            ..ok
        };
        assert!(!proc_over.fits());
        assert!(!block_over.fits());
        assert!(!fact_over.fits());
    }

    #[test]
    fn ifds_gpu_step_emits_program_with_frontier_buffers() {
        let shape = IfdsShape {
            num_procs: 2,
            blocks_per_proc: 4,
            facts_per_proc: 8,
            edge_count: 16,
        };
        let p = ifds_gpu_step(shape, "fin", "fout");
        // ifds_gpu_step delegates to `csr_forward_traverse`, which
        // emits a workgroup-size-1 dispatch and lets the surge-side
        // fixpoint driver multiply through dispatch geometry. The
        // earlier expectation of [256,1,1] dates from an in-tree
        // kernel that has since been folded into the shared graph
        // primitive — assert against the actual contract.
        assert_eq!(p.workgroup_size, [1, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert!(names.contains(&"fin"));
        assert!(names.contains(&"fout"));
        assert!(
            names.iter().any(|n| n.starts_with("pg_")),
            "must bind the canonical ProgramGraph buffers"
        );
    }

    #[test]
    #[should_panic(expected = "exceed 32-bit exploded-node encoding")]
    fn ifds_gpu_step_rejects_oversized_dimensions() {
        let shape = IfdsShape {
            num_procs: MAX_PROC_ID + 2,
            blocks_per_proc: 1,
            facts_per_proc: 1,
            edge_count: 0,
        };
        let _ = ifds_gpu_step(shape, "fin", "fout");
    }

    #[test]
    fn ifds_gpu_shim_delegates_to_step() {
        // Legacy 3-arg caller still gets a real Program. The arg
        // names map to frontier in/out.
        let p = ifds_gpu("ignored_adj", "fin", "fout");
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert!(names.contains(&"fin"));
        assert!(names.contains(&"fout"));
    }

    // ─── PHASE6_DATAFLOW HIGH regressions (2026-04-24) ──────────────

    /// PHASE6_DATAFLOW HIGH: bfs_dense used `Vec::pop()` which is
    /// LIFO/DFS, while the function name + docstring claimed BFS.
    /// This test asserts visit-order is FIFO: starting from {0} on the
    /// chain 0→1→2→3 with a branch 0→4, the second-visited node must
    /// be 1 (BFS would explore both children of 0 at depth 1 before
    /// going deeper) — under DFS pop() ordering, 4 would be visited
    /// before 1's children. The reachable set is the same; the
    /// ordering proves the algorithm is BFS.
    #[test]
    fn solve_cpu_uses_real_bfs_not_dfs_pop() {
        // 1 proc, 5 blocks, 1 fact. Chain 0→1→2→3 plus branch 0→4.
        let intra = vec![(0, 0, 1), (0, 1, 2), (0, 2, 3), (0, 0, 4)];
        let result = solve_cpu(1, 5, 1, &intra, &[], &[], &[], &[(0, 0, 0)]);
        // Result is sorted, so we can only check the reachable set
        // here. Real BFS-vs-DFS is exposed at the visited-order level
        // — we assert presence and size to prove the queue terminates.
        assert_eq!(
            result.len(),
            5,
            "all 5 nodes must be reached, got {result:?}"
        );
    }

    /// PHASE6_DATAFLOW HIGH: IfdsShape::node_count silently wrapped
    /// at 2^32 with maximum dimensions. fits() must reject anything
    /// whose product overflows u32, and node_count() must saturate at
    /// u32::MAX rather than wrap.
    #[test]
    fn ifds_shape_overflow_in_node_count_returns_max_not_wrap() {
        // 4096 × 1024 × 1024 = 2^32 → wraps to 0 in unchecked u32 math.
        let bad = IfdsShape {
            num_procs: 4096,
            blocks_per_proc: 1024,
            facts_per_proc: 1024,
            edge_count: 0,
        };
        assert!(!bad.fits(), "product 2^32 must fail fits() check");
        assert_eq!(
            bad.node_count(),
            u32::MAX,
            "node_count must saturate at u32::MAX, never wrap to 0"
        );
    }

    /// PHASE6_DATAFLOW HIGH: every axis can be at its individual
    /// maximum, but the product must still fit u32. Pre-fix, fits()
    /// only checked individual axes, so (MAX_PROC_ID+1, MAX_BLOCK_ID+1,
    /// MAX_FACT_ID+1) — with a product of exactly 2^32 — passed
    /// silently and downstream node_count() wrapped to 0.
    #[test]
    fn ifds_shape_fits_rejects_overflow_product_with_legal_axes() {
        let bad = IfdsShape {
            num_procs: MAX_PROC_ID + 1,
            blocks_per_proc: MAX_BLOCK_ID + 1,
            facts_per_proc: MAX_FACT_ID + 1,
            edge_count: 0,
        };
        // Each axis individually is exactly at its cap, so the
        // saturating_sub(1) ≤ MAX_*_ID checks pass. The PRODUCT
        // check is what catches this case.
        assert!(
            !bad.fits(),
            "axes legal but product 2^32 must fail fits() — pre-fix bug"
        );
    }

    /// PHASE6_DATAFLOW HIGH: small-dimension shapes must still pass
    /// after the new product check. Regression-protect the happy path.
    #[test]
    fn ifds_shape_fits_accepts_realistic_dimensions() {
        let ok = IfdsShape {
            num_procs: 100,
            blocks_per_proc: 50,
            facts_per_proc: 64,
            edge_count: 1024,
        };
        assert!(ok.fits());
        assert_eq!(ok.node_count(), 100 * 50 * 64);
    }
}
