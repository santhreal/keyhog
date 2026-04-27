//! `reduce_min` — unsigned minimum over a u32 ValueSet.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::reduce::min";

/// Build a Program: `out[0] = min(values)`.
#[must_use]
pub fn reduce_min(values: &str, out: &str, count: u32) -> Program {
    let body = vec![
        Node::let_bind("acc", Expr::u32(u32::MAX)),
        Node::loop_for(
            "i",
            Expr::u32(0),
            Expr::u32(count),
            vec![
                Node::let_bind("v", Expr::load(values, Expr::var("i"))),
                Node::if_then(
                    Expr::lt(Expr::var("v"), Expr::var("acc")),
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
    values.iter().copied().min().unwrap_or(u32::MAX)
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || reduce_min("values", "out", 4),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[9, 3, 7, 5]), to_bytes(&[0])]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[3])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_minimum() {
        assert_eq!(cpu_ref(&[9, 3, 7, 5]), 3);
    }

    #[test]
    fn empty_returns_u32_max() {
        assert_eq!(cpu_ref(&[]), u32::MAX);
    }
}
