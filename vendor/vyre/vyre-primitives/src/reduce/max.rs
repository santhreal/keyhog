//! `reduce_max` — unsigned maximum over a u32 ValueSet.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::reduce::max";

/// Build a Program: `out[0] = max(values)`.
#[must_use]
pub fn reduce_max(values: &str, out: &str, count: u32) -> Program {
    let body = vec![
        Node::let_bind("acc", Expr::u32(0)),
        Node::loop_for(
            "i",
            Expr::u32(0),
            Expr::u32(count),
            vec![
                Node::let_bind("v", Expr::load(values, Expr::var("i"))),
                Node::if_then(
                    Expr::gt(Expr::var("v"), Expr::var("acc")),
                    vec![Node::assign("acc", Expr::var("v"))],
                ),
            ],
        ),
        Node::store(out, Expr::u32(0), Expr::var("acc")),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(values, 0, BufferAccess::ReadOnly, DataType::U32).with_count(count),
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
pub fn cpu_ref(values: &[u32]) -> u32 {
    values.iter().copied().max().unwrap_or(0)
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || reduce_max("values", "out", 4),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[9, 3, 7, 5]), to_bytes(&[0])]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[9])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_maximum() {
        assert_eq!(cpu_ref(&[9, 3, 7, 5]), 9);
    }
}
