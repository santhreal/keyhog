//! Device-side active-frontier queues for sparse CSR expansion.
//!
//! Low-density dataflow frontiers should not launch one useful lane and
//! thousands of empty source-node lanes. This module splits sparse expansion
//! into two GPU-resident primitives:
//!
//! 1. `frontier_to_queue` compacts active source-node ids from a packed bitset
//!    into an active queue with an atomic device-side length.
//! 2. `csr_queue_forward_traverse` consumes only queued sources and expands
//!    their CSR rows into `frontier_out`.
//!
//! The queue length can exceed queue capacity to expose overflow pressure; the
//! traversal consumes only the first `queue_capacity` entries.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::bitset::bitset_words;

/// Canonical op id for bitset-to-queue compaction.
pub const FRONTIER_TO_QUEUE_OP_ID: &str = "vyre-primitives::graph::frontier_to_queue";
/// Canonical op id for queue-driven CSR expansion.
pub const CSR_QUEUE_FORWARD_OP_ID: &str = "vyre-primitives::graph::csr_queue_forward_traverse";

/// Build a GPU program that appends every active frontier node to a queue.
#[must_use]
pub fn frontier_to_queue(
    frontier_in: &str,
    active_queue: &str,
    queue_len: &str,
    node_count: u32,
    queue_capacity: u32,
) -> Program {
    if node_count == 0 || queue_capacity == 0 {
        return crate::invalid_output_program(
            FRONTIER_TO_QUEUE_OP_ID,
            queue_len,
            DataType::U32,
            format!(
                "Fix: frontier_to_queue requires node_count > 0 and queue_capacity > 0, got node_count={node_count} queue_capacity={queue_capacity}."
            ),
        );
    }
    let lane = Expr::InvocationId { axis: 0 };
    let words = bitset_words(node_count);
    let body = vec![
        Node::let_bind("q_src", lane.clone()),
        Node::if_then(
            Expr::lt(Expr::var("q_src"), Expr::u32(node_count)),
            vec![
                Node::let_bind("q_word_idx", Expr::shr(Expr::var("q_src"), Expr::u32(5))),
                Node::let_bind(
                    "q_bit_mask",
                    Expr::shl(
                        Expr::u32(1),
                        Expr::bitand(Expr::var("q_src"), Expr::u32(31)),
                    ),
                ),
                Node::let_bind(
                    "q_src_word",
                    Expr::load(frontier_in, Expr::var("q_word_idx")),
                ),
                Node::if_then(
                    Expr::ne(
                        Expr::bitand(Expr::var("q_src_word"), Expr::var("q_bit_mask")),
                        Expr::u32(0),
                    ),
                    vec![
                        Node::let_bind(
                            "q_slot",
                            Expr::atomic_add(queue_len, Expr::u32(0), Expr::u32(1)),
                        ),
                        Node::if_then(
                            Expr::lt(Expr::var("q_slot"), Expr::u32(queue_capacity)),
                            vec![Node::store(
                                active_queue,
                                Expr::var("q_slot"),
                                Expr::var("q_src"),
                            )],
                        ),
                    ],
                ),
            ],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(frontier_in, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(words),
            BufferDecl::storage(active_queue, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(queue_capacity),
            BufferDecl::storage(queue_len, 2, BufferAccess::ReadWrite, DataType::U32).with_count(1),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(FRONTIER_TO_QUEUE_OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// Build a GPU program that expands only queued CSR source rows.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn csr_queue_forward_traverse(
    active_queue: &str,
    queue_len: &str,
    edge_offsets: &str,
    edge_targets: &str,
    edge_kind_mask: &str,
    frontier_out: &str,
    node_count: u32,
    edge_count: u32,
    queue_capacity: u32,
    allow_mask: u32,
) -> Program {
    if node_count == 0 || queue_capacity == 0 {
        return crate::invalid_output_program(
            CSR_QUEUE_FORWARD_OP_ID,
            frontier_out,
            DataType::U32,
            format!(
                "Fix: csr_queue_forward_traverse requires node_count > 0 and queue_capacity > 0, got node_count={node_count} queue_capacity={queue_capacity}."
            ),
        );
    }
    let lane = Expr::InvocationId { axis: 0 };
    let words = bitset_words(node_count);
    let physical_edge_count = edge_count.max(1);
    let body = vec![
        Node::let_bind("qt_idx", lane.clone()),
        Node::if_then(
            Expr::lt(Expr::var("qt_idx"), Expr::u32(queue_capacity)),
            vec![Node::if_then(
                Expr::lt(Expr::var("qt_idx"), Expr::load(queue_len, Expr::u32(0))),
                vec![
                    Node::let_bind("qt_src", Expr::load(active_queue, Expr::var("qt_idx"))),
                    Node::if_then(
                        Expr::lt(Expr::var("qt_src"), Expr::u32(node_count)),
                        vec![
                            Node::let_bind(
                                "qt_edge_start",
                                Expr::load(edge_offsets, Expr::var("qt_src")),
                            ),
                            Node::let_bind(
                                "qt_edge_end",
                                Expr::load(
                                    edge_offsets,
                                    Expr::add(Expr::var("qt_src"), Expr::u32(1)),
                                ),
                            ),
                            Node::loop_for(
                                "qt_e",
                                Expr::var("qt_edge_start"),
                                Expr::var("qt_edge_end"),
                                vec![Node::if_then(
                                    Expr::lt(Expr::var("qt_e"), Expr::u32(edge_count)),
                                    vec![
                                        Node::let_bind(
                                            "qt_kind",
                                            Expr::load(edge_kind_mask, Expr::var("qt_e")),
                                        ),
                                        Node::if_then(
                                            Expr::ne(
                                                Expr::bitand(
                                                    Expr::var("qt_kind"),
                                                    Expr::u32(allow_mask),
                                                ),
                                                Expr::u32(0),
                                            ),
                                            vec![
                                                Node::let_bind(
                                                    "qt_dst",
                                                    Expr::load(edge_targets, Expr::var("qt_e")),
                                                ),
                                                Node::if_then(
                                                    Expr::lt(
                                                        Expr::var("qt_dst"),
                                                        Expr::u32(node_count),
                                                    ),
                                                    vec![
                                                        Node::let_bind(
                                                            "qt_dst_word",
                                                            Expr::shr(
                                                                Expr::var("qt_dst"),
                                                                Expr::u32(5),
                                                            ),
                                                        ),
                                                        Node::let_bind(
                                                            "qt_dst_bit",
                                                            Expr::shl(
                                                                Expr::u32(1),
                                                                Expr::bitand(
                                                                    Expr::var("qt_dst"),
                                                                    Expr::u32(31),
                                                                ),
                                                            ),
                                                        ),
                                                        Node::let_bind(
                                                            "_qt_prev",
                                                            Expr::atomic_or(
                                                                frontier_out,
                                                                Expr::var("qt_dst_word"),
                                                                Expr::var("qt_dst_bit"),
                                                            ),
                                                        ),
                                                    ],
                                                ),
                                            ],
                                        ),
                                    ],
                                )],
                            ),
                        ],
                    ),
                ],
            )],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(active_queue, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(queue_capacity),
            BufferDecl::storage(queue_len, 1, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage(edge_offsets, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(node_count + 1),
            BufferDecl::storage(edge_targets, 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(physical_edge_count),
            BufferDecl::storage(edge_kind_mask, 4, BufferAccess::ReadOnly, DataType::U32)
                .with_count(physical_edge_count),
            BufferDecl::storage(frontier_out, 5, BufferAccess::ReadWrite, DataType::U32)
                .with_count(words),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(CSR_QUEUE_FORWARD_OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference for queue materialization.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn frontier_to_queue_cpu(
    frontier_in: &[u32],
    node_count: u32,
    queue_capacity: usize,
) -> (Vec<u32>, u32) {
    let mut queue = Vec::with_capacity(queue_capacity);
    let mut seen = 0u32;
    for src in 0..node_count {
        let word = (src / 32) as usize;
        let bit = 1u32 << (src % 32);
        if frontier_in.get(word).copied().unwrap_or(0) & bit == 0 {
            continue;
        }
        if queue.len() < queue_capacity {
            queue.push(src);
        }
        seen = seen.saturating_add(1);
    }
    (queue, seen)
}

/// CPU reference for queue-driven CSR expansion.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn csr_queue_forward_traverse_cpu(
    active_queue: &[u32],
    queue_len: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    node_count: u32,
    allow_mask: u32,
) -> Vec<u32> {
    validate_csr_queue_graph(node_count, edge_offsets, edge_targets, edge_kind_mask)
        .unwrap_or_else(|err| {
            panic!("csr_queue_forward_traverse CPU oracle received malformed input. {err}")
        });
    let mut out = vec![0u32; bitset_words(node_count) as usize];
    let take = (queue_len as usize).min(active_queue.len());
    for &src in &active_queue[..take] {
        if src >= node_count {
            continue;
        }
        let start = edge_offsets[src as usize] as usize;
        let end = edge_offsets[src as usize + 1] as usize;
        for edge in start..end.min(edge_targets.len()).min(edge_kind_mask.len()) {
            if edge_kind_mask[edge] & allow_mask == 0 {
                continue;
            }
            let dst = edge_targets[edge];
            if dst < node_count {
                out[dst as usize / 32] |= 1u32 << (dst % 32);
            }
        }
    }
    out
}

/// Validated resident graph layout for queue-driven sparse traversal.
///
/// The primitive owns these derived counts so resident dispatch wrappers do not
/// fork CSR edge-count, edge-padding, or frontier bitset sizing rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CsrQueueGraphLayout {
    /// Number of graph nodes accepted by the primitive.
    pub node_count: u32,
    /// Exact physical edge count declared by `edge_offsets[node_count]`.
    pub edge_count: u32,
    /// Number of u32 words in each packed frontier bitset.
    pub words: usize,
    /// Number of u32 words to allocate/upload for edge target and kind arrays.
    pub edge_storage_words: usize,
}

/// Validate the CSR graph consumed by queue-driven sparse traversal.
///
/// Returns the resident graph layout so dispatch wrappers can construct padded
/// buffers without owning CSR validation locally.
///
/// # Errors
///
/// Returns an actionable diagnostic for zero-node graphs, malformed offsets,
/// mismatched edge arrays, or out-of-range destinations.
pub fn validate_csr_queue_graph(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
) -> Result<CsrQueueGraphLayout, String> {
    if node_count == 0 {
        return Err("Fix: csr_queue_forward_traverse requires node_count > 0.".to_string());
    }
    let expected_offsets = (node_count as usize).checked_add(1).ok_or_else(|| {
        format!(
            "Fix: csr_queue_forward_traverse node_count + 1 overflows usize for node_count={node_count}."
        )
    })?;
    if edge_offsets.len() != expected_offsets {
        return Err(format!(
            "Fix: csr_queue_forward_traverse requires edge_offsets.len() == node_count + 1, got len={}, node_count={node_count}.",
            edge_offsets.len()
        ));
    }
    if edge_targets.len() != edge_kind_mask.len() {
        return Err(format!(
            "Fix: csr_queue_forward_traverse requires edge_targets.len() == edge_kind_mask.len(), got {} vs {}.",
            edge_targets.len(),
            edge_kind_mask.len()
        ));
    }
    if edge_offsets[0] != 0 {
        return Err(format!(
            "Fix: csr_queue_forward_traverse requires edge_offsets[0] == 0, got {}.",
            edge_offsets[0]
        ));
    }
    for (row, pair) in edge_offsets.windows(2).enumerate() {
        if pair[0] > pair[1] {
            return Err(format!(
                "Fix: csr_queue_forward_traverse offsets must be monotonic at row {row}: {} > {}.",
                pair[0], pair[1]
            ));
        }
    }
    let edge_count = edge_offsets[expected_offsets - 1] as usize;
    if edge_targets.len() != edge_count {
        return Err(format!(
            "Fix: csr_queue_forward_traverse final offset declares edge_count={edge_count}, but targets_len={} and kind_mask_len={}.",
            edge_targets.len(),
            edge_kind_mask.len()
        ));
    }
    for (index, &target) in edge_targets.iter().enumerate() {
        if target >= node_count {
            return Err(format!(
                "Fix: csr_queue_forward_traverse edge_targets[{index}]={target} is outside node_count {node_count}."
            ));
        }
    }
    let edge_count = u32::try_from(edge_count).map_err(|_| {
        format!("Fix: csr_queue_forward_traverse edge count {edge_count} exceeds u32 index space.")
    })?;
    Ok(CsrQueueGraphLayout {
        node_count,
        edge_count,
        words: bitset_words(node_count) as usize,
        edge_storage_words: edge_targets.len().max(1),
    })
}

/// Validate a batch of packed frontiers for queue-driven CSR traversal.
///
/// Returns the exact packed frontier word count implied by `node_count`, so
/// dispatch wrappers can size resident scratch without duplicating the
/// primitive's batch-shape contract.
///
/// # Errors
///
/// Returns an actionable diagnostic for zero-node graphs, empty batches, zero
/// queue capacity, or any query frontier whose packed bitset width does not
/// match `node_count`.
pub fn validate_frontier_queue_batch(
    node_count: u32,
    frontiers: &[&[u32]],
    queue_capacity: u32,
) -> Result<usize, String> {
    if node_count == 0 {
        return Err("Fix: resident CSR queue batch requires node_count > 0.".to_string());
    }
    if frontiers.is_empty() {
        return Err("Fix: resident CSR queue batch requires at least one frontier.".to_string());
    }
    if queue_capacity == 0 {
        return Err("Fix: resident CSR queue batch requires queue_capacity > 0.".to_string());
    }

    let expected_words = bitset_words(node_count) as usize;
    for (query_index, frontier) in frontiers.iter().enumerate() {
        if frontier.len() != expected_words {
            return Err(format!(
                "Fix: resident CSR queue batch query {query_index} expected {expected_words} frontier word(s) for node_count={node_count} but received {}.",
                frontier.len()
            ));
        }
    }
    Ok(expected_words)
}

/// Validate one packed frontier for queue-driven CSR traversal.
///
/// Returns the exact packed frontier word count implied by `node_count`, so a
/// resident dispatch wrapper can size scratch without duplicating queue and
/// frontier-shape policy.
///
/// # Errors
///
/// Returns an actionable diagnostic for zero-node graphs, zero queue capacity,
/// or a frontier whose packed bitset width does not match `node_count`.
pub fn validate_frontier_queue_query(
    node_count: u32,
    frontier: &[u32],
    queue_capacity: u32,
) -> Result<usize, String> {
    validate_frontier_queue_batch(node_count, &[frontier], queue_capacity).map_err(|error| {
        error
            .replace("resident CSR queue batch", "resident CSR queue query")
            .replace("query 0", "query")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_queue_preserves_node_order_and_reports_overflow_pressure() {
        let (queue, len) = frontier_to_queue_cpu(&[0b10111], 5, 3);
        assert_eq!(queue, vec![0, 1, 2]);
        assert_eq!(len, 4);
    }

    #[test]
    fn cpu_queue_traverse_expands_only_queued_sources() {
        let edge_offsets = vec![0, 2, 3, 3, 3];
        let edge_targets = vec![1, 2, 3];
        let edge_kind_mask = vec![1, 2, 1];
        let out = csr_queue_forward_traverse_cpu(
            &[0, 1],
            2,
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            4,
            1,
        );
        assert_eq!(out, vec![0b1010]);
    }

    #[test]
    fn emitted_programs_have_stable_shapes() {
        let queue = frontier_to_queue("frontier", "queue", "len", 64, 8);
        assert_eq!(queue.workgroup_size, [256, 1, 1]);
        assert_eq!(queue.buffers.len(), 3);
        let traverse = csr_queue_forward_traverse(
            "queue", "len", "offsets", "targets", "kinds", "out", 64, 7, 8, 1,
        );
        assert_eq!(traverse.workgroup_size, [256, 1, 1]);
        assert_eq!(traverse.buffers.len(), 6);
    }

    #[test]
    fn validate_csr_queue_graph_accepts_zero_edge_graph_and_canonical_graph() {
        assert_eq!(
            validate_csr_queue_graph(3, &[0, 0, 0, 0], &[], &[]).unwrap(),
            CsrQueueGraphLayout {
                node_count: 3,
                edge_count: 0,
                words: 1,
                edge_storage_words: 1,
            }
        );
        assert_eq!(
            validate_csr_queue_graph(4, &[0, 2, 3, 3, 3], &[1, 2, 3], &[1, 2, 1]).unwrap(),
            CsrQueueGraphLayout {
                node_count: 4,
                edge_count: 3,
                words: 1,
                edge_storage_words: 3,
            }
        );
    }

    #[test]
    fn validate_csr_queue_graph_rejects_malformed_inputs() {
        let err = validate_csr_queue_graph(0, &[0], &[], &[]).unwrap_err();
        assert!(err.contains("node_count > 0"));

        let err = validate_csr_queue_graph(2, &[0, 1, 1], &[1], &[]).unwrap_err();
        assert!(err.contains("edge_targets.len() == edge_kind_mask.len()"));

        let err = validate_csr_queue_graph(2, &[0, 2, 1], &[1], &[1]).unwrap_err();
        assert!(err.contains("offsets must be monotonic"));

        let err = validate_csr_queue_graph(2, &[0, 1, 1], &[5], &[1]).unwrap_err();
        assert!(err.contains("outside node_count"));
    }

    #[test]
    fn validate_frontier_queue_batch_accepts_canonical_frontiers() {
        let frontiers: [&[u32]; 2] = [&[1, 0], &[0, 2]];

        let words = validate_frontier_queue_batch(64, &frontiers, 8)
            .expect("two 64-node frontiers should be valid");

        assert_eq!(words, 2);
    }

    #[test]
    fn validate_frontier_queue_batch_rejects_invalid_batch_shapes() {
        let frontier: [&[u32]; 1] = [&[1]];

        let err = validate_frontier_queue_batch(0, &frontier, 8).unwrap_err();
        assert!(err.contains("node_count > 0"));

        let empty: [&[u32]; 0] = [];
        let err = validate_frontier_queue_batch(64, &empty, 8).unwrap_err();
        assert!(err.contains("at least one frontier"));

        let err = validate_frontier_queue_batch(64, &frontier, 0).unwrap_err();
        assert!(err.contains("queue_capacity > 0"));

        let err = validate_frontier_queue_batch(64, &frontier, 8).unwrap_err();
        assert!(err.contains("query 0 expected 2 frontier word"));
    }

    #[test]
    fn validate_frontier_queue_query_delegates_single_frontier_contract() {
        assert_eq!(validate_frontier_queue_query(64, &[1, 0], 8).unwrap(), 2);

        let err = validate_frontier_queue_query(64, &[1], 8).unwrap_err();
        assert!(err.contains("query expected 2 frontier word"));

        let err = validate_frontier_queue_query(64, &[1, 0], 0).unwrap_err();
        assert!(err.contains("queue_capacity > 0"));
    }
}
