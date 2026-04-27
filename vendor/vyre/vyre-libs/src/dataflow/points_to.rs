//! DF-3 — Andersen points-to, field-sensitive at struct granularity.
//!
//! Unification-based inclusion constraints: `p = &q` adds `q ∈ pts(p)`,
//! `p = q` adds `pts(q) ⊆ pts(p)`, `*p = q` adds `pts(q) ⊆ pts(*x)`
//! for every `x ∈ pts(p)`, etc. Field-sensitive: `pts(p.f)` and
//! `pts(q.g)` are distinct variables even when `p = q` unifies the
//! base objects.
//!
//! # Implementation
//!
//! Andersen's analysis on SSA constraint graph reduces to forward
//! transitive closure: the points-to set of a variable is the set of
//! abstract objects reachable through `subset` edges in the
//! constraint graph. That IS the shape of
//! [`csr_forward_traverse`] — one step per iteration, host loop to
//! fixpoint.
//!
//! The caller lays constraints down as a `ProgramGraph` CSR:
//!   * Nodes = variables + abstract objects.
//!   * Edges = `subset(src, dst)` meaning `pts(src) ⊆ pts(dst)`.
//!   * Seed bits = `addr_of` constraints (variable owns an object).
//!
//! Fixpoint gives `pts(v)` for every variable `v`.
//!
//! Soundness: [`MayOver`](super::Soundness::MayOver). Rules requiring
//! zero-FP MUST compose a downstream sanitizer / type filter.

use vyre::ir::Program;
use vyre_primitives::graph::csr_forward_traverse::{
    bitset_words, cpu_ref as csr_forward_cpu_ref, csr_forward_traverse,
};
use vyre_primitives::graph::program_graph::ProgramGraphShape;

pub(crate) const OP_ID: &str = "vyre-libs::dataflow::points_to";

/// Build one Andersen propagation step. Caller MUST supply the real
/// constraint-graph shape (`node_count`, `edge_count`) so the emitted
/// Program is dispatched at the correct grid size. The current
/// points-to bitset is read from `constraints_in` and the expanded
/// bitset after one subset-edge traversal is written to `pts_out`.
/// Host iterates to fixpoint.
///
/// PHASE6_DATAFLOW HIGH: previous 2-arg entry point hardcoded
/// `ProgramGraphShape::new(1, 1)` — useless for any real constraint
/// graph (single-node grid means only invocation 0 executes the
/// kernel and the rest of the constraint graph is silently ignored).
/// The 2-arg entry was never sound; replaced with the explicit-shape
/// signature below.
///
/// Andersen subset-closure is identical in kernel shape to
/// [`csr_forward_traverse`] *iterated to fixpoint*. A single dispatch
/// of this Program is ONE step — the caller MUST iterate (e.g. via
/// `bitset_fixpoint`) until no new bits propagate.
#[must_use]
pub fn andersen_points_to(
    shape: ProgramGraphShape,
    constraints_in: &str,
    pts_out: &str,
) -> Program {
    csr_forward_traverse(shape, constraints_in, pts_out, u32::MAX)
}

/// Deprecated alias for back-compat with callers that imported the
/// pre-fix name `andersen_points_to_with_shape`. Same semantics as
/// [`andersen_points_to`].
#[deprecated(
    since = "0.6.0",
    note = "use `andersen_points_to(shape, ...)` directly — the name suffix is redundant since the 2-arg entry was removed"
)]
#[must_use]
pub fn andersen_points_to_with_shape(
    shape: ProgramGraphShape,
    constraints_in: &str,
    pts_out: &str,
) -> Program {
    andersen_points_to(shape, constraints_in, pts_out)
}

/// CPU oracle for the transitive subset-closure that
/// [`andersen_points_to`] computes when driven to fixpoint.
///
/// `edge_offsets`, `edge_targets`, and `edge_kind_mask` are the
/// canonical ProgramGraph CSR buffers. `seed_bits` is the initial
/// points-to frontier as a packed u32 bitset. The returned bitset is
/// `seed_bits ∪ reachable(seed_bits)` over all subset edges whose
/// kind mask is non-zero.
///
/// The GPU Program is intentionally one propagation step; callers use
/// this oracle to verify the whole host-driven fixpoint contract.
#[must_use]
pub fn cpu_subset_closure(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed_bits: &[u32],
) -> Vec<u32> {
    let words = bitset_words(node_count) as usize;
    assert_eq!(
        seed_bits.len(),
        words,
        "cpu_subset_closure: seed_bits length must equal bitset_words(node_count)"
    );
    let mut reached = seed_bits.to_vec();
    for _ in 0..node_count {
        let step = csr_forward_cpu_ref(
            node_count,
            edge_offsets,
            edge_targets,
            edge_kind_mask,
            &reached,
            u32::MAX,
        );
        let mut changed = false;
        for (dst, src) in reached.iter_mut().zip(step.iter()) {
            let next = *dst | *src;
            changed |= next != *dst;
            *dst = next;
        }
        if !changed {
            return reached;
        }
    }
    reached
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || andersen_points_to(ProgramGraphShape::new(4, 3), "pts_in", "pts_out"),
        test_inputs: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // Linear subset chain: 0 ⊆ 1 ⊆ 2 ⊆ 3. The output starts
            // with the seed so the convergence lens accumulates
            // reachability instead of replacing it each iteration.
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),    // pg_nodes
                to_bytes(&[0, 1, 2, 3, 3]), // pg_edge_offsets
                to_bytes(&[1, 2, 3]),       // pg_edge_targets
                to_bytes(&[1, 1, 1]),       // pg_edge_kind_mask
                to_bytes(&[0, 0, 0, 0]),    // pg_node_tags
                to_bytes(&[0b0001]),        // pts_in seed
                to_bytes(&[0b0001]),        // pts_out accumulator seed
            ]]
        }),
        expected_output: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // One dispatch advances one subset edge and preserves the
            // accumulator seed. The convergence lens reaches 0b1111.
            vec![vec![to_bytes(&[0b0011])]]
        }),
    }
}

inventory::submit! {
    crate::harness::ConvergenceContract {
        op_id: OP_ID,
        max_iterations: 4096,
    }
}

/// Marker type for the Andersen points-to dataflow primitive.
pub struct PointsTo;

impl super::soundness::SoundnessTagged for PointsTo {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::MayOver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn csr_from_edges(node_count: u32, edges: &[(u32, u32)]) -> (Vec<u32>, Vec<u32>, Vec<u32>) {
        let mut outgoing = vec![Vec::<u32>::new(); node_count as usize];
        for &(src, dst) in edges {
            outgoing[src as usize].push(dst);
        }
        let mut offsets = Vec::with_capacity(node_count as usize + 1);
        let mut targets = Vec::new();
        offsets.push(0);
        for targets_for_node in outgoing {
            targets.extend(targets_for_node);
            offsets.push(targets.len() as u32);
        }
        let edge_count = targets.len().max(1);
        let masks = vec![1; edge_count];
        if targets.is_empty() {
            targets.push(0);
        }
        (offsets, targets, masks)
    }

    fn seed_bitset(node_count: u32, nodes: &[u32]) -> Vec<u32> {
        let mut bits = vec![0; bitset_words(node_count) as usize];
        for &node in nodes {
            let node = node % node_count;
            bits[(node / 32) as usize] |= 1u32 << (node % 32);
        }
        bits
    }

    fn assert_subset(lhs: &[u32], rhs: &[u32]) {
        for (word_index, (left, right)) in lhs.iter().zip(rhs.iter()).enumerate() {
            assert_eq!(
                left & !right,
                0,
                "Fix: points-to closure must be monotone at word {word_index}; left={left:#034b}, right={right:#034b}"
            );
        }
    }

    fn bit_is_set(bits: &[u32], node: u32) -> bool {
        (bits[(node / 32) as usize] & (1u32 << (node % 32))) != 0
    }

    /// PHASE6_DATAFLOW HIGH regression: pre-fix, `andersen_points_to`
    /// was a 2-arg entry point that hardcoded `ProgramGraphShape::new(1, 1)`,
    /// silently producing a 1-node grid. Now the function REQUIRES an
    /// explicit shape, so the emitted Program reflects the caller's
    /// real constraint-graph dimensions.
    #[test]
    fn andersen_points_to_uses_caller_supplied_shape() {
        let shape = ProgramGraphShape::new(64, 128);
        let program = andersen_points_to(shape, "constraints_in", "pts_out");
        // Every node in the constraint graph must get a thread —
        // assert the buffer count matches a non-degenerate shape.
        let frontier_in_count = program
            .buffers
            .iter()
            .find(|b| b.name() == "constraints_in")
            .map(|b| b.count)
            .expect("constraints_in buffer must be declared");
        // bitset_words(64) = 2 (64 bits / 32 bits per u32). NOT 1, which
        // is what the pre-fix hardcoded ProgramGraphShape::new(1, 1)
        // would have produced.
        assert!(
            frontier_in_count >= 2,
            "constraints_in count {frontier_in_count} suggests degenerate 1-node shape — regression"
        );
    }

    /// PHASE6_DATAFLOW HIGH regression: the deprecated alias still
    /// works for back-compat callers but emits the same Program as the
    /// canonical entry. Drop in a future major version.
    #[test]
    #[allow(deprecated)]
    fn deprecated_alias_emits_same_program_shape() {
        let shape = ProgramGraphShape::new(32, 64);
        let canonical = andersen_points_to(shape, "ci", "po");
        let alias = andersen_points_to_with_shape(shape, "ci", "po");
        assert_eq!(
            canonical.workgroup_size, alias.workgroup_size,
            "deprecated alias must delegate to canonical entry"
        );
        assert_eq!(canonical.buffers.len(), alias.buffers.len());
    }

    #[test]
    fn andersen_subset_closure_soundness() {
        let node_count = 4;
        let edges = [(0, 1), (1, 2), (2, 3)];
        let (offsets, targets, masks) = csr_from_edges(node_count, &edges);
        let seed = seed_bitset(node_count, &[0]);

        let closure = cpu_subset_closure(node_count, &offsets, &targets, &masks, &seed);

        for node in 0..node_count {
            assert!(
                bit_is_set(&closure, node),
                "Fix: subset closure must propagate addr-of seed across transitive edge chain; missing node {node}"
            );
        }
    }

    proptest! {
        #[test]
        fn andersen_monotonicity_proptest(
            node_count in 1u32..96,
            raw_edges in prop::collection::vec((0u32..256, 0u32..256), 0..256),
            raw_seed in prop::collection::vec(0u32..256, 0..96),
            raw_extra_seed in prop::collection::vec(0u32..256, 0..96),
        ) {
            let edges = raw_edges
                .into_iter()
                .map(|(src, dst)| (src % node_count, dst % node_count))
                .collect::<Vec<_>>();
            let (offsets, targets, masks) = csr_from_edges(node_count, &edges);
            let seed_a = seed_bitset(node_count, &raw_seed);
            let mut seed_b_nodes = raw_seed;
            seed_b_nodes.extend(raw_extra_seed);
            let seed_b = seed_bitset(node_count, &seed_b_nodes);

            let closure_a = cpu_subset_closure(node_count, &offsets, &targets, &masks, &seed_a);
            let closure_b = cpu_subset_closure(node_count, &offsets, &targets, &masks, &seed_b);

            assert_subset(&seed_a, &seed_b);
            assert_subset(&closure_a, &closure_b);
            assert_subset(&seed_a, &closure_a);
            assert_subset(&seed_b, &closure_b);
        }
    }
}
