//! Canonical ProgramGraph ABI — the 5-buffer CSR bundle every graph
//! primitive in Tier 2.5 consumes.
//!
//! Surgec emits a `ProgramGraph` from `surge::ast::Document`. Every
//! vyre graph primitive takes exactly this buffer shape so a new
//! primitive is "here's the transfer body," not "redeclare the four
//! buffers you want." One ABI makes the primitives composable —
//! `csr_forward_traverse` into `bitset_fixpoint` into `reduce_count`
//! with no glue.
//!
//! # Wire shape
//!
//! ```text
//! +----------------------------------------------------------+
//! | nodes:            u32 buffer    (count = node_count)     |
//! |                   each word = NodeKind tag               |
//! | edge_offsets:     u32 buffer    (count = node_count+1)   |
//! |                   edge_offsets[i]..edge_offsets[i+1]     |
//! |                   is the range into edge_targets for     |
//! |                   outgoing edges of node `i`             |
//! | edge_targets:     u32 buffer    (count = edge_count)     |
//! |                   each word = destination node index     |
//! | edge_kind_mask:   u32 buffer    (count = edge_count)     |
//! |                   each word = bitmask over EdgeKind      |
//! | node_tags:        u32 buffer    (count = node_count)     |
//! |                   each word = bitmask over TagFamily     |
//! +----------------------------------------------------------+
//! ```
//!
//! Edge-kind masks let a single `csr_forward_traverse` restrict to
//! (say) just Assignment + CallArg edges by AND-ing against the
//! per-edge mask. Node tags let `label_family_to_nodeset` emit a
//! frontier bitset without touching the edges.
//!
//! # Invariants
//!
//! - `edge_offsets.len() == node_count + 1`
//! - `edge_targets.len() == edge_count == edge_offsets[node_count]`
//! - `edge_kind_mask.len() == edge_count`
//! - `node_tags.len() == node_count`
//! - `nodes.len() == node_count`
//! - Every `edge_targets[i]` must satisfy `< node_count` or the
//!   primitive raises `Node::Trap`.
//!
//! These invariants are checked by `validate_program_graph` at
//! registration / dispatch time and by the frozen wire format in
//! `vyre-spec`.

use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType};

/// Binding index for the node-kind array.
pub const BINDING_NODES: u32 = 0;
/// Binding index for the CSR row-pointer array.
pub const BINDING_EDGE_OFFSETS: u32 = 1;
/// Binding index for the CSR column array.
pub const BINDING_EDGE_TARGETS: u32 = 2;
/// Binding index for the per-edge kind mask.
pub const BINDING_EDGE_KIND_MASK: u32 = 3;
/// Binding index for the per-node tag mask.
pub const BINDING_NODE_TAGS: u32 = 4;

/// First binding index a primitive is free to use for primitive-
/// specific buffers (frontier bitsets, output arrays, scratch).
pub const BINDING_PRIMITIVE_START: u32 = 5;

/// Canonical buffer name constants — primitives refer to these so
/// every graph-consuming Program shares a single ABI symbol set.
/// Surgec emits CSR blobs under the same names.
pub const NAME_NODES: &str = "pg_nodes";
/// Canonical name for `edge_offsets`.
pub const NAME_EDGE_OFFSETS: &str = "pg_edge_offsets";
/// Canonical name for `edge_targets`.
pub const NAME_EDGE_TARGETS: &str = "pg_edge_targets";
/// Canonical name for `edge_kind_mask`.
pub const NAME_EDGE_KIND_MASK: &str = "pg_edge_kind_mask";
/// Canonical name for `node_tags`.
pub const NAME_NODE_TAGS: &str = "pg_node_tags";

/// Statically-sized CSR dimensions baked into a primitive's
/// [`BufferDecl`] counts so the backend can allocate + layout-validate
/// up front.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgramGraphShape {
    /// Total node count.
    pub node_count: u32,
    /// Total edge count.
    pub edge_count: u32,
}

impl ProgramGraphShape {
    /// Build a shape from a node + edge count.
    #[must_use]
    pub fn new(node_count: u32, edge_count: u32) -> Self {
        Self {
            node_count,
            edge_count,
        }
    }

    /// Emit the five canonical [`BufferDecl`] entries for a primitive
    /// that consumes a read-only ProgramGraph. Primitives add their
    /// own RW output buffers starting at [`BINDING_PRIMITIVE_START`].
    #[must_use]
    pub fn read_only_buffers(&self) -> Vec<BufferDecl> {
        vec![
            BufferDecl::storage(
                NAME_NODES,
                BINDING_NODES,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(self.node_count),
            BufferDecl::storage(
                NAME_EDGE_OFFSETS,
                BINDING_EDGE_OFFSETS,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(self.node_count.saturating_add(1)),
            BufferDecl::storage(
                NAME_EDGE_TARGETS,
                BINDING_EDGE_TARGETS,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(self.edge_count.max(1)),
            BufferDecl::storage(
                NAME_EDGE_KIND_MASK,
                BINDING_EDGE_KIND_MASK,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(self.edge_count.max(1)),
            BufferDecl::storage(
                NAME_NODE_TAGS,
                BINDING_NODE_TAGS,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(self.node_count),
        ]
    }
}

/// Error kinds surfaced by [`validate_program_graph`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphValidationError {
    /// `edge_offsets` length != `node_count + 1`.
    EdgeOffsetsLen {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
    /// `edge_targets` length != `edge_count`.
    EdgeTargetsLen {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
    /// `edge_kind_mask` length != `edge_count`.
    EdgeKindMaskLen {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
    /// `node_tags` length != `node_count`.
    NodeTagsLen {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
    /// `nodes` length != `node_count`.
    NodesLen {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
    /// `edge_targets[i]` >= `node_count`.
    EdgeOutOfRange {
        /// Index into `edge_targets`.
        index: usize,
        /// Observed destination.
        target: u32,
        /// Total node count.
        node_count: u32,
    },
    /// Offsets not monotonically non-decreasing.
    NonMonotonicOffsets {
        /// Index at which the violation was first detected.
        index: usize,
    },
    /// Final CSR offset does not match the declared edge count.
    EdgeCountMismatch {
        /// Declared edge count from the shape.
        expected: usize,
        /// Final offset stored in `edge_offsets[node_count]`.
        got: usize,
    },
}

/// Validate an in-memory `ProgramGraph` against the wire invariants.
///
/// Called by conform harnesses on synthetic fixtures and by surgec on
/// freshly-emitted graphs before dispatch. The backend dispatcher
/// rejects any graph whose CSR breaks these invariants.
pub fn validate_program_graph(
    shape: ProgramGraphShape,
    nodes: &[u32],
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    node_tags: &[u32],
) -> Result<(), GraphValidationError> {
    let n = shape.node_count as usize;
    let e = shape.edge_count as usize;
    if nodes.len() != n {
        return Err(GraphValidationError::NodesLen {
            expected: n,
            got: nodes.len(),
        });
    }
    if edge_offsets.len() != n + 1 {
        return Err(GraphValidationError::EdgeOffsetsLen {
            expected: n + 1,
            got: edge_offsets.len(),
        });
    }
    let expected_edge_len = e.max(1);
    if edge_targets.len() != expected_edge_len {
        return Err(GraphValidationError::EdgeTargetsLen {
            expected: expected_edge_len,
            got: edge_targets.len(),
        });
    }
    if edge_kind_mask.len() != expected_edge_len {
        return Err(GraphValidationError::EdgeKindMaskLen {
            expected: expected_edge_len,
            got: edge_kind_mask.len(),
        });
    }
    if node_tags.len() != n {
        return Err(GraphValidationError::NodeTagsLen {
            expected: n,
            got: node_tags.len(),
        });
    }
    if let Some(&first) = edge_offsets.first() {
        if first != 0 {
            return Err(GraphValidationError::NonMonotonicOffsets { index: 0 });
        }
    }
    for window in edge_offsets.windows(2).enumerate() {
        let (index, pair) = window;
        if pair[1] < pair[0] {
            return Err(GraphValidationError::NonMonotonicOffsets { index });
        }
    }
    let final_offset = edge_offsets.last().copied().unwrap_or_default() as usize;
    if final_offset != e {
        return Err(GraphValidationError::EdgeCountMismatch {
            expected: e,
            got: final_offset,
        });
    }
    for (index, &target) in edge_targets.iter().take(e).enumerate() {
        if target >= shape.node_count {
            return Err(GraphValidationError::EdgeOutOfRange {
                index,
                target,
                node_count: shape.node_count,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_buffers_has_canonical_layout() {
        let bufs = ProgramGraphShape::new(4, 6).read_only_buffers();
        assert_eq!(bufs.len(), 5);
        assert_eq!(bufs[0].name(), NAME_NODES);
        assert_eq!(bufs[1].name(), NAME_EDGE_OFFSETS);
        assert_eq!(bufs[2].name(), NAME_EDGE_TARGETS);
        assert_eq!(bufs[3].name(), NAME_EDGE_KIND_MASK);
        assert_eq!(bufs[4].name(), NAME_NODE_TAGS);
        assert_eq!(bufs[1].count(), 5); // node_count + 1
        assert_eq!(bufs[2].count(), 6); // edge_count
    }

    #[test]
    fn validate_rejects_oob_edge_target() {
        // 3 nodes, 2 edges; one edge points at node 5 (out of range).
        let err = validate_program_graph(
            ProgramGraphShape::new(3, 2),
            &[0, 0, 0],
            &[0, 1, 2, 2],
            &[1, 5],
            &[0, 0],
            &[0, 0, 0],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GraphValidationError::EdgeOutOfRange { target: 5, .. }
        ));
    }

    #[test]
    fn validate_rejects_non_monotonic_offsets() {
        let err = validate_program_graph(
            ProgramGraphShape::new(2, 1),
            &[0, 0],
            &[2, 1, 1], // 2 → 1 is a decrease
            &[0],
            &[0],
            &[0, 0],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GraphValidationError::NonMonotonicOffsets { .. }
        ));
    }

    #[test]
    fn validate_passes_canonical_small_graph() {
        // 3 nodes, 2 edges: 0→1, 1→2
        let ok = validate_program_graph(
            ProgramGraphShape::new(3, 2),
            &[0, 0, 0],
            &[0, 1, 2, 2],
            &[1, 2],
            &[1, 1],
            &[0, 0, 0],
        );
        assert!(ok.is_ok());
    }
}
