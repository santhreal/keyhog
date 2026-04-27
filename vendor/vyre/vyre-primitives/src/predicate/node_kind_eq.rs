//! `node_kind_eq` — `NodeSet = { v : nodes[v] == kind }`.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::predicate::node_kind_eq";

/// Build a Program: `NodeSet = { v : nodes[v] == kind }`.
#[must_use]
pub fn node_kind_eq(nodes: &str, nodeset_out: &str, node_count: u32, kind: u32) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    // AUDIT_2026-04-24 F-PN-01: use canonical `bitset::bitset_words`
    // instead of inlining `div_ceil` so this op never drifts from
    // the crate-wide bitset size convention.
    let words = crate::bitset::bitset_words(node_count);
    let body = vec![
        Node::let_bind("kind_of", Expr::load(nodes, t.clone())),
        Node::if_then(
            Expr::eq(Expr::var("kind_of"), Expr::u32(kind)),
            vec![
                Node::let_bind("word_idx", Expr::shr(t.clone(), Expr::u32(5))),
                Node::let_bind(
                    "bit",
                    Expr::shl(Expr::u32(1), Expr::bitand(t.clone(), Expr::u32(31))),
                ),
                Node::let_bind(
                    "_",
                    Expr::atomic_or(nodeset_out, Expr::var("word_idx"), Expr::var("bit")),
                ),
            ],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(nodes, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(node_count),
            BufferDecl::storage(nodeset_out, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(words),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::lt(t.clone(), Expr::u32(node_count)),
                body,
            )]),
        }],
    )
}

/// CPU reference.
#[must_use]
pub fn cpu_ref(nodes: &[u32], kind: u32) -> Vec<u32> {
    let n = nodes.len() as u32;
    let words = n.div_ceil(32) as usize;
    let mut out = vec![0u32; words];
    for (v, k) in nodes.iter().enumerate() {
        if *k == kind {
            let word = v / 32;
            let bit = 1u32 << (v % 32);
            out[word] |= bit;
        }
    }
    out
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || node_kind_eq("nodes", "nodeset", 4, crate::predicate::node_kind::CALL),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[2, 1, 2, 4]), // nodes: CALL, VARIABLE, CALL, LITERAL
                to_bytes(&[0]),          // nodeset_out
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b0101])]] // nodes 0 and 2 (CALL)
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predicate::node_kind;

    #[test]
    fn filters_by_kind() {
        let got = cpu_ref(
            &[
                node_kind::CALL,
                node_kind::VARIABLE,
                node_kind::CALL,
                node_kind::LITERAL,
            ],
            node_kind::CALL,
        );
        assert_eq!(got, vec![0b0101]);
    }
}
