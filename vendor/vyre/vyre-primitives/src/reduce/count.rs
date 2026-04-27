//! `reduce_count` — population count over a packed bitset, written
//! as a single u32 into `out[0]`.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::reduce::count";

/// Build a Program: `out[0] = sum_{w} popcount(bitset[w])`.
#[must_use]
pub fn reduce_count(bitset: &str, out: &str, words: u32) -> Program {
    let body = vec![
        Node::let_bind("acc", Expr::u32(0)),
        Node::loop_for(
            "w",
            Expr::u32(0),
            Expr::u32(words),
            vec![Node::assign(
                "acc",
                Expr::add(
                    Expr::var("acc"),
                    Expr::UnOp {
                        op: UnOp::Popcount,
                        operand: Box::new(Expr::load(bitset, Expr::var("w"))),
                    },
                ),
            )],
        ),
        Node::store(out, Expr::u32(0), Expr::var("acc")),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(bitset, 0, BufferAccess::ReadOnly, DataType::U32).with_count(words),
            BufferDecl::storage(out, 1, BufferAccess::ReadWrite, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
                body,
            )]),
        }],
    )
}

/// CPU reference.
#[must_use]
pub fn cpu_ref(bitset: &[u32]) -> u32 {
    bitset.iter().map(|w| w.count_ones()).sum()
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || reduce_count("bitset", "out", 2),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b1111, 0xFFFF_FFFF]), to_bytes(&[0])]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[36])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_bit_count() {
        assert_eq!(cpu_ref(&[0b1111, 0xFFFF_FFFF]), 36);
    }
}
