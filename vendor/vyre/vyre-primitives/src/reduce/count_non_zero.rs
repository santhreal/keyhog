//! `reduce_count_non_zero` — count the non-zero lanes in a u32 ValueSet.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::reduce::count_non_zero";

/// Build a Program: `out[0] = |{ i | values[i] != 0 }|`.
#[must_use]
pub fn reduce_count_non_zero(values: &str, out: &str, count: u32) -> Program {
    let body = vec![
        Node::let_bind("acc", Expr::u32(0)),
        Node::loop_for(
            "i",
            Expr::u32(0),
            Expr::u32(count),
            vec![
                Node::let_bind("v", Expr::load(values, Expr::var("i"))),
                Node::assign(
                    "acc",
                    Expr::add(
                        Expr::var("acc"),
                        Expr::select(
                            Expr::ne(Expr::var("v"), Expr::u32(0)),
                            Expr::u32(1),
                            Expr::u32(0),
                        ),
                    ),
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
    values.iter().filter(|&&value| value != 0).count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_non_zero_lanes() {
        assert_eq!(cpu_ref(&[0, 7, 0, 9, 1]), 3);
    }

    #[test]
    fn empty_values_count_zero() {
        assert_eq!(cpu_ref(&[]), 0);
    }
}
