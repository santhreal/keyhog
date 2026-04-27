//! Preorder walk for a **spine** tree encoded like [`vyre_foundation::vast::VastNode`]
//! (`first_child` chain from root `0`, `next_sibling` = sentinel).
//!
//! The v0 GPU composition follows `first_child` edges until [`vyre_foundation::vast::SENTINEL`].
//! General trees use [`vyre_foundation::vast::walk_preorder_indices`] on the host until a
//! stack-backed GPU walker lands (see `docs/PARSING_EXECUTION_PLAN.md` P5).

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::region::wrap_anonymous;

const OP_ID: &str = "vyre-libs::graph::ast_walk_preorder";

/// Pack a spine fixture: full VAST bytes plus the node-table slice (for harness + tests).
pub(crate) fn pack_spine_fixture(node_count: u32) -> (Vec<u8>, Vec<u8>) {
    let full = vyre_foundation::vast::pack_spine_vast(&vec![1u32; node_count as usize]);
    let node_len = (node_count as usize) * vyre_foundation::vast::NODE_STRIDE_U32 * 4;
    let start = vyre_foundation::vast::HEADER_LEN;
    let region = full[start..start + node_len].to_vec();
    (full, region)
}

/// Emit preorder node indices for a `first_child` spine starting at root `0`.
#[must_use]
pub fn ast_walk_preorder(nodes: &str, out: &str, node_count: u32, out_cap: u32) -> Program {
    let stride = vyre_foundation::vast::NODE_STRIDE_U32 as u32;
    let node_words = node_count.saturating_mul(stride).max(1);
    let out_words = out_cap.max(1);
    let body = vec![
        Node::let_bind("oi", Expr::u32(0)),
        Node::let_bind("n", Expr::u32(0)),
        Node::loop_for(
            "step",
            Expr::u32(0),
            Expr::u32(node_count),
            vec![
                Node::if_then(
                    Expr::ge(Expr::var("oi"), Expr::u32(out_cap)),
                    vec![Node::return_()],
                ),
                Node::Block(vec![
                    Node::let_bind(
                        "fc_idx",
                        Expr::add(Expr::mul(Expr::var("n"), Expr::u32(stride)), Expr::u32(2)),
                    ),
                    Node::let_bind("fc", Expr::load(nodes, Expr::var("fc_idx"))),
                    Node::store(out, Expr::var("oi"), Expr::var("n")),
                    Node::assign("oi", Expr::add(Expr::var("oi"), Expr::u32(1))),
                    Node::if_then(
                        Expr::eq(Expr::var("fc"), Expr::u32(vyre_foundation::vast::SENTINEL)),
                        vec![Node::return_()],
                    ),
                    Node::assign("n", Expr::var("fc")),
                ]),
            ],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(nodes, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(node_words),
            BufferDecl::storage(out, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(out_words),
        ],
        [1, 1, 1],
        vec![wrap_anonymous(OP_ID, body)],
    )
}

fn preorder_harness_inputs() -> Vec<Vec<Vec<u8>>> {
    let (_, node_region) = pack_spine_fixture(4);
    let outz = vec![0u8; 32];
    vec![vec![node_region, outz]]
}

fn preorder_harness_expected() -> Vec<Vec<Vec<u8>>> {
    let (_, node_region) = pack_spine_fixture(4);
    let order = vyre_foundation::vast::walk_preorder_indices(&node_region, 4, 128).unwrap();
    let mut out = vec![0u8; 32];
    for (i, &v) in order.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&v.to_le_bytes());
    }
    vec![vec![out]]
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || ast_walk_preorder("nodes", "out", 4, 8),
        test_inputs: Some(preorder_harness_inputs),
        expected_output: Some(preorder_harness_expected),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preorder_program_validates() {
        let p = ast_walk_preorder("nodes", "out", 4, 8);
        assert!(vyre::validate(&p).is_empty());
    }
}
