//! DF-2 companion — live variables (backward dataflow dual of
//! reaching-defs).
//!
//! ```text
//!   out[n] = ⋃ in[s] for s ∈ succ(n)
//!   in[n]  = use[n] ∪ (out[n] − def[n])
//! ```
//!
//! Shipped as one backward-CFG step; surgec's fixpoint driver
//! iterates. The primitive walks the caller-supplied forward CFG in
//! reverse direction, restricted to real control-flow edges.
//!
//! Soundness: `MayOver`.

use vyre::ir::Program;
use vyre_primitives::graph::csr_backward_traverse::csr_backward_traverse;
use vyre_primitives::graph::program_graph::ProgramGraphShape;
use vyre_primitives::predicate::edge_kind;

pub(crate) const OP_ID: &str = "vyre-libs::dataflow::live";
const CFG_EDGE_MASK: u32 = edge_kind::CONTROL;

#[must_use]
/// Build one backward live-variable propagation step over a forward CFG.
pub fn live_step(shape: ProgramGraphShape, frontier_in: &str, frontier_out: &str) -> Program {
    crate::region::tag_program(
        OP_ID,
        csr_backward_traverse(shape, frontier_in, frontier_out, CFG_EDGE_MASK),
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || live_step(ProgramGraphShape::new(4, 3), "fin", "fout"),
        test_inputs: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // Forward CFG: 0→1→2→3. Backward liveness from node 3
            // reaches node 2 after one reverse step.
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),
                to_bytes(&[0, 1, 2, 3, 3]),
                to_bytes(&[1, 2, 3]),
                to_bytes(&[CFG_EDGE_MASK, CFG_EDGE_MASK, CFG_EDGE_MASK]),
                to_bytes(&[0, 0, 0, 0]),
                to_bytes(&[0b1000]),
                to_bytes(&[0b1000]),
            ]]
        }),
        expected_output: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b1100])]]
        }),
    }
}

inventory::submit! {
    crate::harness::ConvergenceContract {
        op_id: OP_ID,
        max_iterations: 64,
    }
}

/// Marker type for the live-variables dataflow primitive.
pub struct Liveness;

impl super::soundness::SoundnessTagged for Liveness {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::MayOver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataflow::reaching;
    use vyre_primitives::predicate::edge_kind;

    #[test]
    fn live_step_uses_control_edge_mask() {
        let p = live_step(ProgramGraphShape::new(4, 3), "fin", "fout");
        assert!(vyre::validate(&p).is_empty());
        // The Program body encodes the edge mask as a u32 literal.
        // We verify the mask excludes dataflow edges and is restricted to CONTROL.
        assert_eq!(CFG_EDGE_MASK, edge_kind::CONTROL);
        assert_eq!(CFG_EDGE_MASK & edge_kind::ASSIGNMENT, 0);
        assert_eq!(CFG_EDGE_MASK & edge_kind::DOMINANCE, 0);
    }

    #[test]
    fn live_step_emits_frontier_buffers() {
        let p = live_step(ProgramGraphShape::new(4, 3), "fin", "fout");
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert!(names.contains(&"fin"));
        assert!(names.contains(&"fout"));
    }

    #[test]
    fn live_step_backward_traversal_shape_matches_input() {
        let shape = ProgramGraphShape::new(64, 128);
        let p = live_step(shape, "fin", "fout");
        let fin_buf = p
            .buffers
            .iter()
            .find(|b| b.name() == "fin")
            .expect("fin buffer");
        assert!(
            fin_buf.count >= 2,
            "bitset_words(64) = 2; count {fin_buf_count} looks degenerate",
            fin_buf_count = fin_buf.count
        );
    }

    #[test]
    fn live_soundness_is_mayover() {
        use super::super::soundness::{Soundness, SoundnessTagged};
        assert_eq!(Liveness.soundness(), Soundness::MayOver);
    }

    #[test]
    fn live_step_mixed_edge_kind_mask_filters_non_control() {
        // M8 adversarial: backward graph with mixed edge kinds.
        // Forward edges: 0→3 (DOMINANCE), 1→3 (ASSIGNMENT), 2→3 (CONTROL).
        // Mask = CONTROL only. frontier_in = {3}.
        // Only node 2 (the CONTROL predecessor) should be reached.
        let got = vyre_primitives::graph::csr_backward_traverse::cpu_ref(
            4,
            &[0, 1, 2, 3, 3], // offsets: each node has 1 outgoing edge except node 3
            &[3, 3, 3],       // targets: 0→3, 1→3, 2→3
            &[
                edge_kind::DOMINANCE,  // filtered
                edge_kind::ASSIGNMENT, // filtered
                edge_kind::CONTROL,    // passes
            ],
            &[0b1000], // frontier_in = {3}
            edge_kind::CONTROL,
        );
        assert_eq!(
            got,
            vec![0b0100],
            "ASSIGNMENT and DOMINANCE predecessors must NOT light up when mask is CONTROL only"
        );
    }

    #[test]
    fn live_step_is_not_structurally_identical_to_reaching() {
        // M6 regression protection: live.rs must NOT produce the same
        // IR as reaching.rs. They encode different traversal directions.
        let live_p = live_step(ProgramGraphShape::new(4, 3), "fin", "fout");
        let reaching_p = reaching::reaching_defs_step(ProgramGraphShape::new(4, 3), "fin", "fout");

        let live_generator = live_p.entry.iter().find_map(|n| {
            if let vyre::ir::Node::Region { body, .. } = n {
                body.iter().find_map(|inner| {
                    if let vyre::ir::Node::Region { generator, .. } = inner {
                        Some(generator.as_str())
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        });
        let reaching_generator = reaching_p.entry.iter().find_map(|n| {
            if let vyre::ir::Node::Region { body, .. } = n {
                body.iter().find_map(|inner| {
                    if let vyre::ir::Node::Region { generator, .. } = inner {
                        Some(generator.as_str())
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        });

        assert_ne!(
            live_generator,
            reaching_generator,
            "live.rs and reaching.rs must NOT produce structurally identical IR — M6 bug"
        );
        assert_eq!(
            live_generator,
            Some("vyre-primitives::graph::csr_backward_traverse"),
            "live_step must emit backward traversal"
        );
        assert_eq!(
            reaching_generator,
            Some("vyre-primitives::graph::csr_forward_traverse"),
            "reaching_defs_step must emit forward traversal"
        );
    }

    #[test]
    fn live_step_backward_reachability_on_test_graph() {
        // Concrete backward-reachability witness.
        // Forward CFG: 0→1→2→3. Backward from {3} should reach {2}
        // after one step, then {1} after two.
        let one_step = vyre_primitives::graph::csr_backward_traverse::cpu_ref(
            4,
            &[0, 1, 2, 3, 3],
            &[1, 2, 3],
            &[edge_kind::CONTROL, edge_kind::CONTROL, edge_kind::CONTROL],
            &[0b1000],
            edge_kind::CONTROL,
        );
        assert_eq!(one_step, vec![0b0100], "one backward step from {{3}} reaches {{2}}");

        let two_step = vyre_primitives::graph::csr_backward_traverse::cpu_ref(
            4,
            &[0, 1, 2, 3, 3],
            &[1, 2, 3],
            &[edge_kind::CONTROL, edge_kind::CONTROL, edge_kind::CONTROL],
            &one_step,
            edge_kind::CONTROL,
        );
        assert_eq!(two_step, vec![0b0010], "two backward steps from {{3}} reaches {{1}}");
    }

    #[test]
    fn live_step_fixpoint_converges_on_cycle() {
        // Backward cycle: 0→1, 1→2, 2→0. All CONTROL.
        // Seed {0}. iter1: predecessors of {0} = {2}
        // iter2: predecessors of {0,2} = {1,2}
        // iter3: predecessors of {0,1,2} = {0,1,2} → converged
        let mut frontier = vec![0b0001];
        let words = vyre_primitives::graph::csr_forward_traverse::bitset_words(3) as usize;
        frontier.resize(words, 0);
        let mut iters = 0;
        for _ in 0..128 {
            let next = vyre_primitives::graph::csr_backward_traverse::cpu_ref(
                3,
                &[0, 1, 2, 3],
                &[1, 2, 0],
                &[edge_kind::CONTROL, edge_kind::CONTROL, edge_kind::CONTROL],
                &frontier,
                edge_kind::CONTROL,
            );
            let mut changed = false;
            for i in 0..words {
                let old = frontier[i];
                frontier[i] |= next[i];
                if frontier[i] != old {
                    changed = true;
                }
            }
            iters += 1;
            if !changed {
                break;
            }
        }
        assert!(
            iters > 1,
            "backward fixpoint on a cycle must take >1 iteration; converged in {iters}"
        );
        assert_eq!(
            frontier,
            vec![0b0111],
            "all nodes in backward cycle must be reachable"
        );
    }
}
