//! `motif` — intersect edge witnesses for a small graph pattern.
//!
//! Each motif edge is checked independently against the canonical
//! ProgramGraph CSR. If every requested motif edge exists, every
//! endpoint participating in the motif is marked in the final witness.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::graph::program_graph::{
    ProgramGraphShape, BINDING_PRIMITIVE_START, NAME_EDGE_KIND_MASK, NAME_EDGE_OFFSETS,
    NAME_EDGE_TARGETS,
};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::graph::motif";

/// One directed motif edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MotifEdge {
    /// Source node id.
    pub from: u32,
    /// Edge-kind mask that must match.
    pub kind_mask: u32,
    /// Destination node id.
    pub to: u32,
}

/// Build a Program: one invocation checks every motif edge, records
/// participating endpoint bits only for matched edges, and publishes
/// the participant union if the whole motif matched.
///
/// # Panics
///
/// Panics if `edges.len() > u32::MAX`. AUDIT_2026-04-24 F-MOTIF-04:
/// prior code silently truncated `edges.len() as u32`, so a caller
/// with >4B motif edges would emit a kernel that reads past the
/// intended edge window and silently "matches" on trailing garbage.
/// A motif with >4B edges is pathological by construction, but the
/// truncation was fail-silent — now fail-loud at the builder site
/// where the real contract violation lives.
#[must_use]
pub fn motif(shape: ProgramGraphShape, edges: &[MotifEdge], witness_out: &str) -> Program {
    let edge_count = u32::try_from(edges.len()).expect(
        "motif: edges.len() exceeds u32::MAX — a motif with >4B edges is not representable \
         by the u32 edge-count contract; split the motif or redesign the caller",
    );
    let mut buffers = shape.read_only_buffers();
    buffers.push(
        BufferDecl::storage(
            "motif_from",
            BINDING_PRIMITIVE_START,
            BufferAccess::ReadOnly,
            DataType::U32,
        )
        .with_count(edge_count.max(1)),
    );
    buffers.push(
        BufferDecl::storage(
            "motif_kind",
            BINDING_PRIMITIVE_START + 1,
            BufferAccess::ReadOnly,
            DataType::U32,
        )
        .with_count(edge_count.max(1)),
    );
    buffers.push(
        BufferDecl::storage(
            "motif_to",
            BINDING_PRIMITIVE_START + 2,
            BufferAccess::ReadOnly,
            DataType::U32,
        )
        .with_count(edge_count.max(1)),
    );
    buffers.push(
        BufferDecl::storage(
            "motif_hits",
            BINDING_PRIMITIVE_START + 3,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(shape.node_count.max(1)),
    );
    buffers.push(
        BufferDecl::storage(
            witness_out,
            BINDING_PRIMITIVE_START + 4,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(shape.node_count.max(1)),
    );

    let clear_outputs = vec![
        Node::store("motif_hits", Expr::var("node"), Expr::u32(0)),
        Node::store(witness_out, Expr::var("node"), Expr::u32(0)),
    ];
    // AUDIT_2026-04-24 F-MOT-02: guard `src < node_count` before
    // loading `NAME_EDGE_OFFSETS[src]` and `NAME_EDGE_OFFSETS[src+1]`
    // so a hand-crafted motif with `from >= node_count` cannot read
    // past the graph offsets buffer on the GPU.
    let scan_edge = vec![
        Node::let_bind("src", Expr::load("motif_from", Expr::var("m"))),
        Node::let_bind("dst", Expr::load("motif_to", Expr::var("m"))),
        Node::let_bind("want_kind", Expr::load("motif_kind", Expr::var("m"))),
        Node::let_bind("edge_found", Expr::u32(0)),
        Node::if_then(
            Expr::lt(Expr::var("src"), Expr::u32(shape.node_count)),
            vec![
                Node::let_bind(
                    "edge_start",
                    Expr::load(NAME_EDGE_OFFSETS, Expr::var("src")),
                ),
                Node::let_bind(
                    "edge_end",
                    Expr::load(NAME_EDGE_OFFSETS, Expr::add(Expr::var("src"), Expr::u32(1))),
                ),
                Node::loop_for(
                    "e",
                    Expr::var("edge_start"),
                    Expr::var("edge_end"),
                    vec![
                        Node::let_bind("actual_dst", Expr::load(NAME_EDGE_TARGETS, Expr::var("e"))),
                        Node::let_bind(
                            "actual_kind",
                            Expr::load(NAME_EDGE_KIND_MASK, Expr::var("e")),
                        ),
                        Node::if_then(
                            Expr::and(
                                Expr::eq(Expr::var("actual_dst"), Expr::var("dst")),
                                Expr::ne(
                                    Expr::bitand(Expr::var("actual_kind"), Expr::var("want_kind")),
                                    Expr::u32(0),
                                ),
                            ),
                            vec![Node::assign("edge_found", Expr::u32(1))],
                        ),
                    ],
                ),
            ],
        ),
        Node::if_then(
            Expr::ne(Expr::var("edge_found"), Expr::u32(0)),
            vec![
                Node::assign(
                    "matched_edges",
                    Expr::add(Expr::var("matched_edges"), Expr::u32(1)),
                ),
                Node::store("motif_hits", Expr::var("src"), Expr::u32(1)),
                Node::store("motif_hits", Expr::var("dst"), Expr::u32(1)),
            ],
        ),
    ];
    let materialize = vec![Node::store(
        witness_out,
        Expr::var("node"),
        Expr::load("motif_hits", Expr::var("node")),
    )];

    // PHASE7_GRAPH C2: motif is fundamentally serial — one thread loops
    // over every motif edge in order and accumulates `matched_edges`.
    // Using a [256,1,1] workgroup with a `gid_x() == 0` gate burns 255
    // idle lanes per workgroup. Dispatch a single 1-lane workgroup
    // instead so the wasted parallelism is gone, and drop the redundant
    // gate.
    Program::wrapped(
        buffers,
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![
                Node::loop_for(
                    "node",
                    Expr::u32(0),
                    Expr::u32(shape.node_count),
                    clear_outputs,
                ),
                Node::let_bind("matched_edges", Expr::u32(0)),
                Node::loop_for("m", Expr::u32(0), Expr::u32(edge_count), scan_edge),
                Node::if_then(
                    Expr::eq(Expr::var("matched_edges"), Expr::u32(edge_count)),
                    vec![Node::loop_for(
                        "node",
                        Expr::u32(0),
                        Expr::u32(shape.node_count),
                        materialize,
                    )],
                ),
            ]),
        }],
    )
}

/// CPU reference: return one byte-per-node witness set where `1`
/// means the node participates in a complete motif match.
#[must_use]
pub fn cpu_ref(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    motif_edges: &[MotifEdge],
) -> Vec<u32> {
    let mut participants = vec![0u32; node_count as usize];
    let mut matched_edges = 0u32;
    for motif_edge in motif_edges {
        let mut found = false;
        // AUDIT_2026-04-24 F-MOTIF-01/02/03: silent fall-through
        // previously masked malformed CSR. Fail loudly.
        let start = edge_offsets
            .get(motif_edge.from as usize)
            .copied()
            .expect("motif cpu_ref: edge_offsets[from] missing — malformed CSR")
            as usize;
        let end = edge_offsets
            .get(motif_edge.from as usize + 1)
            .copied()
            .expect("motif cpu_ref: edge_offsets[from + 1] missing — malformed CSR")
            as usize;
        for edge_idx in start..end {
            let dst = edge_targets
                .get(edge_idx)
                .copied()
                .expect("motif cpu_ref: edge_targets[idx] missing — malformed CSR");
            let kind = edge_kind_mask
                .get(edge_idx)
                .copied()
                .expect("motif cpu_ref: edge_kind_mask[idx] missing — malformed CSR");
            if dst == motif_edge.to && (kind & motif_edge.kind_mask) != 0 {
                found = true;
            }
        }
        if !found {
            return vec![0; node_count as usize];
        }
        matched_edges += 1;
        if let Some(hit) = participants.get_mut(motif_edge.from as usize) {
            *hit = 1;
        }
        if let Some(hit) = participants.get_mut(motif_edge.to as usize) {
            *hit = 1;
        }
    }
    if matched_edges == motif_edges.len() as u32 {
        participants
    } else {
        vec![0; node_count as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_node_chain_motif_marks_every_participant() {
        let witness = cpu_ref(
            3,
            &[0, 1, 2, 2],
            &[1, 2],
            &[1, 1],
            &[
                MotifEdge {
                    from: 0,
                    kind_mask: 1,
                    to: 1,
                },
                MotifEdge {
                    from: 1,
                    kind_mask: 1,
                    to: 2,
                },
            ],
        );
        assert_eq!(witness, vec![1, 1, 1]);
    }

    #[test]
    fn missing_motif_edge_clears_all_participants() {
        let witness = cpu_ref(
            3,
            &[0, 1, 1, 1],
            &[1],
            &[1],
            &[
                MotifEdge {
                    from: 0,
                    kind_mask: 1,
                    to: 1,
                },
                MotifEdge {
                    from: 1,
                    kind_mask: 1,
                    to: 2,
                },
            ],
        );
        assert_eq!(witness, vec![0, 0, 0]);
    }
}
