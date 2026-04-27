//! `level_wave_program` — GPU-resident depth-wave dispatcher for
//! bottom-up callee-before-caller computations.
//!
//! Semantically distinct from
//! [`fixpoint::persistent_fixpoint`](crate::fixpoint::persistent_fixpoint):
//! - **persistent_fixpoint**: re-run a transfer step until convergence.
//!   No depth ordering — every lane runs the step every iteration.
//! - **level_wave**: deterministic ordered traversal. Each lane runs
//!   the step only when `current_depth == depth[lane]`. Used for
//!   bottom-up summary computations where children must complete
//!   before parents.
//!
//! ## LEGO discipline
//!
//! Composes:
//! - [`toposort`](super::toposort) — CPU reference for the depth
//!   assignment (caller computes `depth[node]` from the topological
//!   ordering before invoking this primitive).
//! - `Node::Loop` (vyre-foundation IR primitive) — outer per-depth
//!   loop.
//! - `Node::Barrier` — synchronisation between depth waves.
//! - `Expr::eq` + `Node::if_then` — depth predicate per lane.
//!
//! No new sub-op invented. The caller composes its own per-lane work
//! body; this primitive provides the wave harness.
//!
//! ## Composition contract
//!
//! Caller supplies:
//!
//! - `depth_buf`: per-node depth bitset (u32 per lane). The lane
//!   reads its own depth and gates its work on equality with the
//!   current wave depth.
//! - `step_body`: caller-provided IR body that runs ONE node's work.
//!   Reads `current_depth` and `depth_buf[lane]`; the
//!   level_wave_program guards the body in `if depth == current`
//!   already, so the body itself doesn't need to re-check.
//! - `max_depth`: maximum depth value in the topology.
//!
//! Caller receives a [`Program`] that, when dispatched once, runs
//! every lane at every depth wave from 0..max_depth. Barriers between
//! waves ensure depth-N work is fully complete before depth-N+1
//! starts.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::graph::level_wave";

/// Build a Program that runs `step_body` per lane in
/// depth-ordered waves.
///
/// Each lane reads `depth_buf[invocation_id]`. The kernel walks
/// `current_depth = 0..max_depth`. At each depth, every lane whose
/// depth equals `current_depth` executes `step_body`. A `Barrier` is
/// emitted between depths so the caller can rely on depth-N effects
/// being globally visible before depth-N+1 begins.
///
/// # Parameters
///
/// - `step_body`: caller's per-lane work body. Free to read/write
///   any buffer the caller declares; it does NOT need to re-check
///   the depth predicate (the wrapper does that).
/// - `depth_buf`: buffer-name holding per-lane depth (u32). Read-only.
/// - `max_depth`: number of waves to execute.
/// - `lane_count`: total number of lanes in the dispatch grid.
#[must_use]
pub fn level_wave_program(
    step_body: Vec<Node>,
    depth_buf: &str,
    max_depth: u32,
    lane_count: u32,
) -> Program {
    let lane = Expr::InvocationId { axis: 0 };
    let depth_for_lane = Expr::load(depth_buf, lane.clone());

    let body = vec![Node::loop_for(
        "__lw_depth__",
        Expr::u32(0),
        Expr::u32(max_depth),
        vec![
            // Per-lane gate: only the lanes whose declared depth
            // matches the current wave participate.
            Node::if_then(
                Expr::and(
                    Expr::lt(lane.clone(), Expr::u32(lane_count)),
                    Expr::eq(depth_for_lane.clone(), Expr::var("__lw_depth__")),
                ),
                step_body.clone(),
            ),
            // Wave barrier: every lane waits here so depth-N
            // effects are globally visible before depth-N+1 starts.
            Node::Barrier,
        ],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(depth_buf, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(lane_count),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU oracle. Iterates depth waves on the host and calls
/// `step_for_lane(lane, depth)` exactly once per (lane, depth ==
/// depth_for_lane[lane]). Used by the conformance harness to verify
/// that the GPU kernel respects the depth ordering.
pub fn cpu_ref<F>(depths: &[u32], max_depth: u32, mut step_for_lane: F)
where
    F: FnMut(u32, u32),
{
    for current_depth in 0..max_depth {
        for (lane_idx, lane_depth) in depths.iter().enumerate() {
            if *lane_depth == current_depth {
                step_for_lane(lane_idx as u32, current_depth);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_ref_visits_each_lane_at_its_depth() {
        let depths = vec![0u32, 1, 2, 1, 0];
        let mut visits: Vec<(u32, u32)> = Vec::new();
        cpu_ref(&depths, 3, |lane, depth| visits.push((lane, depth)));
        // Every lane visited exactly once, in depth order.
        assert_eq!(visits.len(), depths.len());
        for (idx, &(lane, depth)) in visits.iter().enumerate() {
            assert_eq!(depth, depths[lane as usize]);
            // Visits are sorted by depth (waves).
            if idx > 0 {
                assert!(depth >= visits[idx - 1].1);
            }
        }
    }

    #[test]
    fn program_shape_matches_contract() {
        let step = vec![Node::store("out", Expr::u32(0), Expr::u32(1))];
        let program = level_wave_program(step, "depths", 8, 64);
        assert!(
            program.buffers.iter().any(|b| b.name() == "depths"),
            "depth buffer must be declared"
        );
    }
}
