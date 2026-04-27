//! `csr_bidirectional` — one BFS step over BOTH forward + backward
//! edges of a ProgramGraph CSR. Used for undirected reachability
//! (e.g. component discovery, alias unification).

use vyre_foundation::execution_plan::fusion::fuse_programs;
use vyre_foundation::ir::Program;

use crate::graph::csr_backward_traverse::csr_backward_traverse;
use crate::graph::csr_forward_traverse::csr_forward_traverse;
use crate::graph::program_graph::ProgramGraphShape;

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::graph::csr_bidirectional";

/// Build a Program: emit one forward step + one backward step,
/// fused into one Region. Both writes target `frontier_out` so a
/// single dispatch covers both directions.
#[must_use]
pub fn csr_bidirectional(
    shape: ProgramGraphShape,
    frontier_in: &str,
    frontier_out: &str,
    edge_kind_mask: u32,
) -> Program {
    let fwd = csr_forward_traverse(shape, frontier_in, frontier_out, edge_kind_mask);
    let bwd = csr_backward_traverse(shape, frontier_in, frontier_out, edge_kind_mask);
    fuse_programs(&[fwd, bwd]).expect("csr_bidirectional: forward+backward must fuse cleanly")
}

/// CPU reference: union of forward + backward one-step reach.
#[must_use]
pub fn cpu_ref(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
) -> Vec<u32> {
    use crate::graph::csr_backward_traverse::cpu_ref as bwd_ref;
    use crate::graph::csr_forward_traverse::cpu_ref as fwd_ref;
    let f = fwd_ref(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
        allow_mask,
    );
    let b = bwd_ref(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
        allow_mask,
    );
    f.into_iter().zip(b).map(|(x, y)| x | y).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linear_graph() -> (Vec<u32>, Vec<u32>, Vec<u32>) {
        // 0 -> 1 -> 2 -> 3
        (vec![0, 1, 2, 3, 3], vec![1, 2, 3], vec![1, 1, 1])
    }

    #[test]
    fn forward_step_propagates() {
        let (off, tgt, msk) = linear_graph();
        let out = cpu_ref(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF);
        // 0's forward neighbor = 1 → bit 1 set.
        assert!(out[0] & 0b0010 != 0);
    }

    #[test]
    fn empty_seed_yields_empty_step() {
        let (off, tgt, msk) = linear_graph();
        let out = cpu_ref(4, &off, &tgt, &msk, &[0], 0xFFFF_FFFF);
        assert_eq!(out, vec![0]);
    }

    #[test]
    fn allow_mask_zero_blocks_all() {
        let (off, tgt, msk) = linear_graph();
        let out = cpu_ref(4, &off, &tgt, &msk, &[0b0001], 0);
        assert_eq!(out, vec![0]);
    }

    #[test]
    fn bidirectional_includes_both_directions() {
        let (off, tgt, msk) = linear_graph();
        // From {1}, forward reaches {2}; backward reaches {0}.
        let out = cpu_ref(4, &off, &tgt, &msk, &[0b0010], 0xFFFF_FFFF);
        assert!(out[0] & 0b0001 != 0, "bwd should reach node 0");
        assert!(out[0] & 0b0100 != 0, "fwd should reach node 2");
    }
}
