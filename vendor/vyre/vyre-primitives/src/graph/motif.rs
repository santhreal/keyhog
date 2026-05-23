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

/// Validated motif dispatch layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MotifLayout {
    /// Number of graph nodes and output words.
    pub node_count: u32,
    /// Number of graph nodes and output words, widened for host buffer sizing.
    pub output_words: usize,
    /// Number of physical CSR edges.
    pub edge_count: u32,
    /// Number of u32 words required by physical edge buffers after padding.
    pub edge_storage_words: usize,
    /// Number of requested motif edges.
    pub motif_edge_count: u32,
}

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
/// Invalid motif sizes lower to an explicit trap program. Prior code
/// silently truncated `edges.len() as u32`; this path keeps the failure
/// executable without crashing the host process.
#[must_use]
pub fn motif(shape: ProgramGraphShape, edges: &[MotifEdge], witness_out: &str) -> Program {
    let Ok(edge_count) = u32::try_from(edges.len()) else {
        return crate::invalid_output_program(
            OP_ID,
            witness_out,
            DataType::U32,
            "Fix: motif edges.len() exceeds u32::MAX; split the motif or redesign the caller."
                .to_string(),
        );
    };
    let mut buffers = shape.read_only_buffers();
    buffers.push(
        BufferDecl::storage(
            "motif_hits",
            BINDING_PRIMITIVE_START,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(shape.node_count.max(1)),
    );
    buffers.push(
        BufferDecl::storage(
            witness_out,
            BINDING_PRIMITIVE_START + 1,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(shape.node_count.max(1)),
    );

    let clear_outputs = vec![
        Node::store("motif_hits", Expr::var("node"), Expr::u32(0)),
        Node::store(witness_out, Expr::var("node"), Expr::u32(0)),
    ];
    // Motif edges are compile-time operands of this generated program, not
    // runtime graph data. Lowering them as constants removes three input
    // buffers and prevents loop-carried scratch state from making a partial
    // motif look like a complete match.
    let mut scan_edges = Vec::with_capacity(edges.len().saturating_mul(5));
    let mut mark_hits = Vec::with_capacity(edges.len().saturating_mul(2));
    for (idx, edge) in edges.iter().enumerate() {
        let edge_found = format!("edge_found_{idx}");
        let edge_start = format!("edge_start_{idx}");
        let edge_end = format!("edge_end_{idx}");
        let edge_index = format!("e_{idx}");
        let actual_dst = format!("actual_dst_{idx}");
        let actual_kind = format!("actual_kind_{idx}");
        scan_edges.push(Node::let_bind(&edge_found, Expr::u32(0)));
        if edge.from < shape.node_count {
            scan_edges.push(Node::let_bind(
                &edge_start,
                Expr::load(NAME_EDGE_OFFSETS, Expr::u32(edge.from)),
            ));
            scan_edges.push(Node::let_bind(
                &edge_end,
                Expr::load(NAME_EDGE_OFFSETS, Expr::u32(edge.from.saturating_add(1))),
            ));
            scan_edges.push(Node::loop_for(
                &edge_index,
                Expr::var(&edge_start),
                Expr::var(&edge_end),
                vec![
                    Node::let_bind(
                        &actual_dst,
                        Expr::load(NAME_EDGE_TARGETS, Expr::var(&edge_index)),
                    ),
                    Node::let_bind(
                        &actual_kind,
                        Expr::load(NAME_EDGE_KIND_MASK, Expr::var(&edge_index)),
                    ),
                    Node::if_then(
                        Expr::and(
                            Expr::eq(Expr::var(&actual_dst), Expr::u32(edge.to)),
                            Expr::ne(
                                Expr::bitand(Expr::var(&actual_kind), Expr::u32(edge.kind_mask)),
                                Expr::u32(0),
                            ),
                        ),
                        vec![Node::assign(&edge_found, Expr::u32(1))],
                    ),
                ],
            ));
        }
        scan_edges.push(Node::if_then(
            Expr::ne(Expr::var(&edge_found), Expr::u32(0)),
            vec![Node::assign(
                "matched_edges",
                Expr::add(Expr::var("matched_edges"), Expr::u32(1)),
            )],
        ));
        if edge.from < shape.node_count {
            mark_hits.push(Node::store(
                "motif_hits",
                Expr::u32(edge.from),
                Expr::u32(1),
            ));
        }
        if edge.to < shape.node_count {
            mark_hits.push(Node::store("motif_hits", Expr::u32(edge.to), Expr::u32(1)));
        }
    }
    let materialize = vec![Node::store(
        witness_out,
        Expr::var("node"),
        Expr::load("motif_hits", Expr::var("node")),
    )];
    let mut publish_full_match = mark_hits;
    publish_full_match.push(Node::loop_for(
        "node",
        Expr::u32(0),
        Expr::u32(shape.node_count),
        materialize,
    ));

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
                Node::Block(scan_edges),
                Node::if_then(
                    Expr::eq(Expr::var("matched_edges"), Expr::u32(edge_count)),
                    publish_full_match,
                ),
            ]),
        }],
    )
}

/// CPU reference: return one byte-per-node witness set where `1`
/// means the node participates in a complete motif match.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    motif_edges: &[MotifEdge],
) -> Vec<u32> {
    let mut participants = Vec::new();
    cpu_ref_into(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        motif_edges,
        &mut participants,
    );
    participants
}

/// CPU reference into caller-owned witness storage.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref_into(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    motif_edges: &[MotifEdge],
    participants: &mut Vec<u32>,
) {
    participants.clear();
    participants.resize(node_count as usize, 0);
    validate_csr_inputs(node_count, edge_offsets, edge_targets, edge_kind_mask)
        .unwrap_or_else(|err| panic!("motif CPU oracle received malformed input. {err}"));
    if !motif_all_edges_present(edge_offsets, edge_targets, edge_kind_mask, motif_edges) {
        return;
    }
    for motif_edge in motif_edges {
        if let Some(hit) = participants.get_mut(motif_edge.from as usize) {
            *hit = 1;
        }
        if let Some(hit) = participants.get_mut(motif_edge.to as usize) {
            *hit = 1;
        }
    }
}

/// Return true iff the complete motif exists.
///
/// This avoids allocating a full witness vector for existence checks.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref_matches(
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    motif_edges: &[MotifEdge],
) -> bool {
    motif_all_edges_present(edge_offsets, edge_targets, edge_kind_mask, motif_edges)
}

/// Count distinct nodes participating in a complete motif match.
///
/// This avoids materializing the witness vector when callers only need a
/// scheduling signal.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref_participation_count(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    motif_edges: &[MotifEdge],
) -> u32 {
    validate_csr_inputs(node_count, edge_offsets, edge_targets, edge_kind_mask)
        .unwrap_or_else(|err| panic!("motif participation oracle received malformed input. {err}"));
    if !motif_all_edges_present(edge_offsets, edge_targets, edge_kind_mask, motif_edges) {
        return 0;
    }
    let mut participants = vec![0u32; node_count as usize];
    for motif_edge in motif_edges {
        if let Some(hit) = participants.get_mut(motif_edge.from as usize) {
            *hit = 1;
        }
        if let Some(hit) = participants.get_mut(motif_edge.to as usize) {
            *hit = 1;
        }
    }
    participants.into_iter().filter(|&value| value != 0).count() as u32
}

/// Validate the public CSR inputs consumed by the motif primitive.
///
/// Returns the exact edge count declared by `edge_offsets[node_count]`, so
/// dispatch wrappers can pad zero-edge buffers without duplicating CSR
/// validation logic.
///
/// # Errors
///
/// Returns an actionable diagnostic for malformed row offsets, edge arrays, or
/// out-of-range destinations.
pub fn validate_csr_inputs(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
) -> Result<MotifLayout, String> {
    validate_motif_inputs(node_count, edge_offsets, edge_targets, edge_kind_mask, &[])
}

/// Validate the public CSR and motif inputs consumed by the motif primitive.
///
/// # Errors
///
/// Returns an actionable diagnostic for malformed row offsets, edge arrays,
/// out-of-range destinations, or motif edge counts that exceed u32 dispatch
/// metadata.
pub fn validate_motif_inputs(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    motif_edges: &[MotifEdge],
) -> Result<MotifLayout, String> {
    let expected_offsets = (node_count as usize).checked_add(1).ok_or_else(|| {
        format!("Fix: motif node_count + 1 overflows usize for node_count={node_count}.")
    })?;
    if edge_offsets.len() != expected_offsets {
        return Err(format!(
            "Fix: motif requires edge_offsets.len() == node_count + 1, got len={}, node_count={node_count}.",
            edge_offsets.len()
        ));
    }
    if edge_targets.len() != edge_kind_mask.len() {
        return Err(format!(
            "Fix: motif requires edge_targets.len() == edge_kind_mask.len(), got {} vs {}.",
            edge_targets.len(),
            edge_kind_mask.len()
        ));
    }
    if let Some(&first) = edge_offsets.first() {
        if first != 0 {
            return Err(format!(
                "Fix: motif requires edge_offsets[0] == 0, got {first}."
            ));
        }
    }
    for (index, pair) in edge_offsets.windows(2).enumerate() {
        if pair[0] > pair[1] {
            return Err(format!(
                "Fix: motif offsets must be monotonic; offsets[{index}]={} > offsets[{}]={}.",
                pair[0],
                index + 1,
                pair[1]
            ));
        }
    }
    let edge_count = edge_offsets[expected_offsets - 1] as usize;
    if edge_targets.len() != edge_count {
        return Err(format!(
            "Fix: motif final offset declares edge_count={edge_count}, but targets_len={} and kind_mask_len={}.",
            edge_targets.len(),
            edge_kind_mask.len()
        ));
    }
    for (index, &target) in edge_targets.iter().enumerate() {
        if target >= node_count {
            return Err(format!(
                "Fix: motif edge_targets[{index}]={target} is outside node_count {node_count}."
            ));
        }
    }
    let edge_count = u32::try_from(edge_count)
        .map_err(|_| format!("Fix: motif edge count {edge_count} exceeds u32 index space."))?;
    let motif_edge_count = u32::try_from(motif_edges.len()).map_err(|_| {
        format!(
            "Fix: motif edge pattern count {} exceeds u32 index space.",
            motif_edges.len()
        )
    })?;
    Ok(MotifLayout {
        node_count,
        output_words: node_count as usize,
        edge_count,
        edge_storage_words: edge_targets.len().max(1),
        motif_edge_count,
    })
}

/// Count nonzero witness entries using the primitive's u32 result contract.
///
/// # Errors
///
/// Returns an actionable diagnostic if the witness vector is too large to
/// report with the primitive's u32 count metadata.
pub fn count_witness_participants(witness: &[u32]) -> Result<u32, String> {
    let count = witness.iter().filter(|&&value| value != 0).count();
    u32::try_from(count)
        .map_err(|_| format!("Fix: motif witness participant count {count} exceeds u32::MAX."))
}

#[cfg(any(test, feature = "cpu-parity"))]
fn motif_all_edges_present(
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    motif_edges: &[MotifEdge],
) -> bool {
    for motif_edge in motif_edges {
        let Some(start) = edge_offsets.get(motif_edge.from as usize).copied() else {
            return false;
        };
        let Some(end) = edge_offsets.get(motif_edge.from as usize + 1).copied() else {
            return false;
        };
        let start = start as usize;
        let end = end as usize;
        let mut found = false;
        for edge_idx in start..end {
            let Some(dst) = edge_targets.get(edge_idx).copied() else {
                break;
            };
            let Some(kind) = edge_kind_mask.get(edge_idx).copied() else {
                break;
            };
            if dst == motif_edge.to && (kind & motif_edge.kind_mask) != 0 {
                found = true;
                break;
            }
        }
        if !found {
            return false;
        }
    }
    true
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || motif(ProgramGraphShape::new(4, 4), &[MotifEdge { from: 0, to: 1, kind_mask: 1 }], "witness"),
        None,
        None,
    )
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

    #[test]
    fn cpu_ref_into_reuses_witness_storage() {
        let mut witness = Vec::with_capacity(8);
        cpu_ref_into(
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
            &mut witness,
        );
        let capacity = witness.capacity();
        assert_eq!(witness, vec![1, 1, 1]);

        cpu_ref_into(
            3,
            &[0, 1, 1, 1],
            &[1],
            &[1],
            &[MotifEdge {
                from: 1,
                kind_mask: 1,
                to: 2,
            }],
            &mut witness,
        );
        assert_eq!(witness.capacity(), capacity);
        assert_eq!(witness, vec![0, 0, 0]);
    }

    #[test]
    fn allocation_free_predicates_match_witness_contract() {
        let motif = [
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
        ];
        assert!(cpu_ref_matches(&[0, 1, 2, 2], &[1, 2], &[1, 1], &motif));
        assert_eq!(
            cpu_ref_participation_count(3, &[0, 1, 2, 2], &[1, 2], &[1, 1], &motif),
            3
        );
        assert!(!cpu_ref_matches(&[0, 1, 1, 1], &[1], &[1], &motif));
        assert_eq!(
            cpu_ref_participation_count(3, &[0, 1, 1, 1], &[1], &[1], &motif),
            0
        );
        assert!(
            cpu_ref_matches(&[0, 1, 2, 2], &[1, 2], &[1, 1], &[]),
            "empty motif has no missing edges"
        );
        assert_eq!(
            cpu_ref_participation_count(3, &[0, 1, 2, 2], &[1, 2], &[1, 1], &[]),
            0,
            "empty motif has no participating nodes"
        );
    }

    #[test]
    fn validate_csr_inputs_accepts_empty_and_canonical_graphs() {
        assert_eq!(
            validate_motif_inputs(0, &[0], &[], &[], &[]).unwrap(),
            MotifLayout {
                node_count: 0,
                output_words: 0,
                edge_count: 0,
                edge_storage_words: 1,
                motif_edge_count: 0,
            }
        );
        assert_eq!(
            validate_motif_inputs(
                3,
                &[0, 1, 2, 2],
                &[1, 2],
                &[1, 1],
                &[MotifEdge {
                    from: 0,
                    kind_mask: 1,
                    to: 1,
                }],
            )
            .unwrap(),
            MotifLayout {
                node_count: 3,
                output_words: 3,
                edge_count: 2,
                edge_storage_words: 2,
                motif_edge_count: 1,
            }
        );
    }

    #[test]
    fn witness_participant_count_uses_primitive_contract() {
        assert_eq!(count_witness_participants(&[1, 0, 2, 0]).unwrap(), 2);
    }

    #[test]
    fn validate_csr_inputs_rejects_malformed_csr() {
        let err = validate_csr_inputs(2, &[0, 1, 1], &[1], &[]).unwrap_err();
        assert!(err.contains("edge_targets.len() == edge_kind_mask.len()"));

        let err = validate_csr_inputs(2, &[0, 2, 1], &[1], &[1]).unwrap_err();
        assert!(err.contains("offsets must be monotonic"));

        let err = validate_csr_inputs(2, &[0, 1, 1], &[5], &[1]).unwrap_err();
        assert!(err.contains("outside node_count"));
    }
}
