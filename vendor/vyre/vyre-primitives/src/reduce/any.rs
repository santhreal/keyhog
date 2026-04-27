//! `reduce_any` — emit `1` when any lane in a u32 ValueSet is non-zero.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::reduce::any";

/// Build a Program: `out[0] = any(values[i] != 0)`.
///
/// The accumulation uses `atomic_or` against `out[0]` directly, with a
/// single `Node::store` to the identity (0) on entry. Two reasons:
///
/// 1. The lowered IR carries an `AtomicOp::Or` node that downstream
///    passes (and the `quantifier_lowering_short_circuits` test) can
///    inspect to confirm short-circuit semantics on the GPU.
/// 2. When a future caller fans this out across multiple workgroups,
///    the atomic stays correct without any further code change — the
///    plain `bitor` pattern would race.
#[must_use]
pub fn reduce_any(values: &str, out: &str, count: u32) -> Program {
    let body = vec![
        Node::store(out, Expr::u32(0), Expr::u32(0)),
        Node::loop_for(
            "i",
            Expr::u32(0),
            Expr::u32(count),
            vec![
                Node::let_bind("v", Expr::load(values, Expr::var("i"))),
                Node::let_bind(
                    "_acc_prev",
                    Expr::atomic_or(
                        out,
                        Expr::u32(0),
                        Expr::select(
                            Expr::ne(Expr::var("v"), Expr::u32(0)),
                            Expr::u32(1),
                            Expr::u32(0),
                        ),
                    ),
                ),
            ],
        ),
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
    if values.iter().any(|&value| value != 0) {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_is_true_when_one_lane_is_non_zero() {
        assert_eq!(cpu_ref(&[0, 0, 1, 0]), 1);
    }

    #[test]
    fn any_is_false_for_all_zero() {
        assert_eq!(cpu_ref(&[0, 0, 0]), 0);
    }
}
