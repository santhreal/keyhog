//! One persistent-BFS workgroup step with coalesced change detection.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::{GeneratorRef, Ident};
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::graph::csr_forward_or_changed::csr_forward_or_changed_child;
use crate::graph::program_graph::{ProgramGraphShape, BINDING_PRIMITIVE_START};
use crate::reduce::workgroup_any::workgroup_any_u32_child;

/// Canonical op id for one persistent-BFS workgroup-coalesced step.
pub const PERSISTENT_BFS_STEP_OP_ID: &str = "vyre-primitives::graph::persistent_bfs_step";

/// Build one reusable persistent-BFS step body.
#[must_use]
pub fn persistent_bfs_step_body(
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed: &str,
    scratch: &str,
    edge_kind_mask: u32,
) -> Vec<Node> {
    let t = Expr::gid_x();
    vec![
        Node::let_bind("local_changed", Expr::u32(0)),
        Node::store(scratch, Expr::local_x(), Expr::u32(0)),
        Node::barrier(),
        Node::if_then(
            Expr::lt(t, Expr::u32(shape.node_count)),
            vec![csr_forward_or_changed_child(
                PERSISTENT_BFS_STEP_OP_ID,
                shape,
                frontier_out,
                "local_changed",
                edge_kind_mask,
            )],
        ),
        Node::store(scratch, Expr::local_x(), Expr::var("local_changed")),
        Node::barrier(),
        Node::if_then(
            Expr::eq(Expr::local_x(), Expr::u32(0)),
            vec![
                Node::let_bind("any_changed", Expr::u32(0)),
                workgroup_any_u32_child(PERSISTENT_BFS_STEP_OP_ID, scratch, "any_changed", 256),
                Node::if_then(
                    Expr::ne(Expr::var("any_changed"), Expr::u32(0)),
                    vec![Node::let_bind(
                        "_",
                        Expr::atomic_or(changed, Expr::u32(0), Expr::u32(1)),
                    )],
                ),
            ],
        ),
        Node::barrier(),
    ]
}

/// Wrap the persistent-BFS step as a child of `parent_op_id`.
#[must_use]
pub fn persistent_bfs_step_child(
    parent_op_id: &str,
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed: &str,
    scratch: &str,
    edge_kind_mask: u32,
) -> Node {
    Node::Region {
        generator: Ident::from(PERSISTENT_BFS_STEP_OP_ID),
        source_region: Some(GeneratorRef {
            name: parent_op_id.to_string(),
        }),
        body: Arc::new(persistent_bfs_step_body(
            shape,
            frontier_out,
            changed,
            scratch,
            edge_kind_mask,
        )),
    }
}

/// Standalone one-step program for primitive-level conformance.
#[must_use]
pub fn persistent_bfs_step(
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed: &str,
    edge_kind_mask: u32,
) -> Program {
    let words = crate::bitset::bitset_words(shape.node_count).max(1);
    let mut buffers = shape.read_only_buffers();
    buffers.push(
        BufferDecl::storage(
            frontier_out,
            BINDING_PRIMITIVE_START,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(words),
    );
    buffers.push(
        BufferDecl::storage(
            changed,
            BINDING_PRIMITIVE_START + 1,
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
            generator: Ident::from(PERSISTENT_BFS_STEP_OP_ID),
            source_region: None,
            body: Arc::new(persistent_bfs_step_body(
                shape,
                frontier_out,
                changed,
                "wg_scratch",
                edge_kind_mask,
            )),
        }],
    )
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        PERSISTENT_BFS_STEP_OP_ID,
        || persistent_bfs_step(ProgramGraphShape::new(4, 4), "frontier_out", "changed", 0xFFFF_FFFF),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),
                to_bytes(&[0, 2, 3, 4, 4]),
                to_bytes(&[1, 2, 3, 3]),
                to_bytes(&[1, 1, 1, 1]),
                to_bytes(&[0, 0, 0, 0]),
                to_bytes(&[0b0001]),
                to_bytes(&[0]),
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b1111]), to_bytes(&[1])]]
        }),
    )
}
