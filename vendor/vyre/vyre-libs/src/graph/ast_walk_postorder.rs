//! Postorder walk over a **spine** tree (`first_child` chain, `next_sibling`
//! = [`vyre_foundation::vast::SENTINEL`]). Matches [`super::ast_walk_preorder`]
//! fixtures: indices `0..node_count-1` in reverse.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::region::wrap_anonymous;

const OP_ID: &str = "vyre-libs::graph::ast_walk_postorder";

/// Emit `node_count - 1 - i` into `out[i]` for `i in 0..node_count` (spine postorder).
#[must_use]
pub fn ast_walk_postorder(out: &str, node_count: u32) -> Program {
    let out_words = node_count.max(1);
    let body = vec![Node::loop_for(
        "i",
        Expr::u32(0),
        Expr::u32(node_count),
        vec![Node::store(
            out,
            Expr::var("i"),
            Expr::sub(Expr::u32(node_count.saturating_sub(1)), Expr::var("i")),
        )],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(out, 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(out_words),
        ],
        [1, 1, 1],
        vec![wrap_anonymous(OP_ID, body)],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || ast_walk_postorder("out", 4),
        test_inputs: Some(|| {
            let z = vec![0u8; 16];
            vec![vec![z]]
        }),
        expected_output: Some(|| {
            let mut w = Vec::new();
            for v in [3u32, 2, 1, 0] {
                w.extend_from_slice(&v.to_le_bytes());
            }
            vec![vec![w]]
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::super::ast_walk_preorder::pack_spine_fixture;
    use super::*;

    #[test]
    fn postorder_matches_host_reverse_of_preorder_spine() {
        let (_, node_region) = pack_spine_fixture(4);
        let pre = vyre_foundation::vast::walk_preorder_indices(&node_region, 4, 128).unwrap();
        let post = vyre_foundation::vast::walk_postorder_indices(&node_region, 4, 128).unwrap();
        let rev: Vec<u32> = pre.iter().rev().copied().collect();
        assert_eq!(post, rev);
        let p = ast_walk_postorder("out", 4);
        assert!(
            vyre::validate(&p).is_empty(),
            "postorder program must validate"
        );
    }
}
