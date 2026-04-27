//! `persistent_bfs` — on-device multi-step BFS frontier expansion.
//!
//! The kernel copies `frontier_in` into `frontier_out`, then performs up to
//! `max_iters` forward traversal steps, accumulating reachable nodes into
//! `frontier_out` via atomic OR.  The first `min(max_iters, 4)` iterations
//! are unrolled and use a workgroup-local `wg_scratch` buffer to coalesce
//! per-workgroup change detection between steps.
//!
use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::graph::persistent_bfs_step::persistent_bfs_step_child;
use crate::graph::program_graph::{ProgramGraphShape, BINDING_PRIMITIVE_START};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::graph::persistent_bfs";

/// Canonical binding index for the input frontier bitset.
pub const BINDING_FRONTIER_IN: u32 = BINDING_PRIMITIVE_START;
/// Canonical binding index for the output frontier bitset.
pub const BINDING_FRONTIER_OUT: u32 = BINDING_PRIMITIVE_START + 1;
/// Canonical binding index for the global changed flag.
pub const BINDING_CHANGED: u32 = BINDING_PRIMITIVE_START + 2;

/// Words needed to hold a bitset over `node_count` nodes.
#[must_use]
pub const fn bitset_words(node_count: u32) -> u32 {
    crate::bitset::bitset_words(node_count)
}

/// Build the IR `Program` for persistent BFS.
///
/// The kernel copies `frontier_in` into `frontier_out`, then performs up
/// to `max_iters` forward traversal steps.  The first four iterations are
/// unrolled with inter-step workgroup barriers and a shared `wg_scratch`
/// array; any additional iterations run in a plain bounded loop.
///
/// `changed` is a single u32 word that is set to `1` if *any* step produced
/// a new reachable node.
#[must_use]
pub fn persistent_bfs(
    shape: ProgramGraphShape,
    frontier_in: &str,
    frontier_out: &str,
    edge_kind_mask: u32,
    max_iters: u32,
) -> Program {
    let words = bitset_words(shape.node_count);
    let t = Expr::gid_x();

    let unrolled_iter = || -> Node {
        persistent_bfs_step_child(
            OP_ID,
            shape,
            frontier_out,
            "changed",
            "wg_scratch",
            edge_kind_mask,
        )
    };

    let mut entry: Vec<Node> = vec![
        // Seed frontier_out from frontier_in.
        Node::let_bind("word_idx", t.clone()),
        Node::if_then(
            Expr::lt(Expr::var("word_idx"), Expr::u32(words)),
            vec![Node::store(
                frontier_out,
                Expr::var("word_idx"),
                Expr::load(frontier_in, Expr::var("word_idx")),
            )],
        ),
        // Zero the global changed flag.
        Node::if_then(
            Expr::eq(t.clone(), Expr::u32(0)),
            vec![Node::store("changed", Expr::u32(0), Expr::u32(0))],
        ),
        // Barrier clears fusion hazards from the plain store above before the
        // first atomic access inside the unrolled steps.
        Node::barrier(),
    ];

    let unroll_count = max_iters.min(4);
    for _ in 0..unroll_count {
        entry.push(unrolled_iter());
    }

    let remaining = max_iters.saturating_sub(unroll_count);
    if remaining > 0 {
        entry.push(Node::loop_for(
            "iter",
            Expr::u32(0),
            Expr::u32(remaining),
            vec![
                Node::let_bind("local_changed", Expr::u32(0)),
                Node::if_then(
                    Expr::lt(t.clone(), Expr::u32(shape.node_count)),
                    vec![
                        crate::graph::csr_forward_or_changed::csr_forward_or_changed_child(
                            OP_ID,
                            shape,
                            frontier_out,
                            "local_changed",
                            edge_kind_mask,
                        ),
                    ],
                ),
                Node::if_then(
                    Expr::eq(Expr::var("local_changed"), Expr::u32(1)),
                    vec![Node::let_bind(
                        "_",
                        Expr::atomic_or("changed", Expr::u32(0), Expr::u32(1)),
                    )],
                ),
            ],
        ));
    }

    let mut buffers = shape.read_only_buffers();
    buffers.push(
        BufferDecl::storage(
            frontier_in,
            BINDING_FRONTIER_IN,
            BufferAccess::ReadOnly,
            DataType::U32,
        )
        .with_count(words.max(1)),
    );
    buffers.push(
        BufferDecl::storage(
            frontier_out,
            BINDING_FRONTIER_OUT,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(words.max(1)),
    );
    buffers.push(
        BufferDecl::storage(
            "changed",
            BINDING_CHANGED,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(1),
    );
    buffers.push(BufferDecl::workgroup("wg_scratch", 256, DataType::U32));

    Program::wrapped(
        buffers,
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(entry),
        }],
    )
}

/// CPU reference: run BFS up to `max_iters` steps, accumulating into a
/// running bitset.  Returns the final frontier and a sticky `changed`
/// flag (`1` if any step added new nodes, else `0`).
#[must_use]
pub fn cpu_ref(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
    max_iters: u32,
) -> (Vec<u32>, u32) {
    let words = bitset_words(node_count) as usize;
    let mut out = frontier_in.to_vec();
    let mut changed = 0u32;

    for _ in 0..max_iters {
        let step = crate::graph::csr_forward_traverse::cpu_ref(
            node_count,
            edge_offsets,
            edge_targets,
            edge_kind_mask,
            &out,
            allow_mask,
        );
        let mut step_changed = false;
        for w in 0..words {
            let old = out[w];
            out[w] |= step[w];
            if out[w] != old {
                step_changed = true;
            }
        }
        if step_changed {
            changed = 1;
        } else {
            break;
        }
    }

    // Ensure length matches the declared word count even if frontier_in
    // was shorter (defensive — the conform harness sizes buffers exactly).
    out.resize(words, 0);
    (out, changed)
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || persistent_bfs(ProgramGraphShape::new(4, 4), "fin", "fout", 0xFFFF_FFFF, 4),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),          // pg_nodes
                to_bytes(&[0, 2, 3, 4, 4]),       // pg_edge_offsets
                to_bytes(&[1, 2, 3, 3]),          // pg_edge_targets
                to_bytes(&[1, 1, 1, 1]),          // pg_edge_kind_mask
                to_bytes(&[0, 0, 0, 0]),          // pg_node_tags
                to_bytes(&[0b0001]),              // frontier_in = {0}
                to_bytes(&[0]),                   // frontier_out
                to_bytes(&[0]),                   // changed
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // After 4 iterations the graph 0→1,0→2,1→3,2→3 is fully closed.
            vec![vec![
                to_bytes(&[0b1111]),              // frontier_out = {0,1,2,3}
                to_bytes(&[1]),                   // changed
            ]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_bfs_reaches_closure() {
        let (frontier, changed) = cpu_ref(
            4,
            &[0, 2, 3, 4, 4],
            &[1, 2, 3, 3],
            &[1, 1, 1, 1],
            &[0b0001],
            0xFFFF_FFFF,
            4,
        );
        assert_eq!(frontier, vec![0b1111]);
        assert_eq!(changed, 1);
    }

    #[test]
    fn empty_frontier_stays_empty() {
        let (frontier, changed) = cpu_ref(
            4,
            &[0, 2, 3, 4, 4],
            &[1, 2, 3, 3],
            &[1, 1, 1, 1],
            &[0],
            0xFFFF_FFFF,
            4,
        );
        assert_eq!(frontier, vec![0]);
        assert_eq!(changed, 0);
    }

    #[test]
    fn edge_mask_limits_reachability() {
        // 0→1 (mask 0b10), 0→2 (mask 0b01), 1→3 (mask 0b01), 2→3 (mask 0b01)
        let (frontier, changed) = cpu_ref(
            4,
            &[0, 2, 3, 4, 4],
            &[1, 2, 3, 3],
            &[0b10, 0b01, 0b01, 0b01],
            &[0b0001],
            0b01,
            4,
        );
        // From 0, only 0→2 is allowed. Then 2→3 is allowed.
        assert_eq!(frontier, vec![0b1101]);
        assert_eq!(changed, 1);
    }

    #[test]
    fn max_iters_caps_expansion() {
        // Chain: 0→1, 1→2, 2→3. Frontier = {0}.
        let (frontier, changed) = cpu_ref(
            4,
            &[0, 1, 2, 3, 3],
            &[1, 2, 3],
            &[1, 1, 1],
            &[0b0001],
            0xFFFF_FFFF,
            2,
        );
        // After 2 steps: {0,1,2}
        assert_eq!(frontier, vec![0b0111]);
        assert_eq!(changed, 1);
    }

    #[test]
    fn zero_max_iters_is_noop() {
        let (frontier, changed) = cpu_ref(
            4,
            &[0, 2, 3, 4, 4],
            &[1, 2, 3, 3],
            &[1, 1, 1, 1],
            &[0b0001],
            0xFFFF_FFFF,
            0,
        );
        assert_eq!(frontier, vec![0b0001]);
        assert_eq!(changed, 0);
    }

    #[test]
    fn program_builds_and_validates() {
        let program = persistent_bfs(ProgramGraphShape::new(8, 8), "fin", "fout", 0xFF, 4);
        assert_eq!(program.workgroup_size, [1, 1, 1]);
        // 5 canonical PG buffers + frontier_in + frontier_out + changed + wg_scratch
        assert_eq!(program.buffers().len(), 9);
    }
}
