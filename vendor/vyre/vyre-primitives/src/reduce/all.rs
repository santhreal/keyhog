//! `reduce_all` — emit `1` when every lane in a u32 ValueSet is non-zero.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::reduce::all";

/// Build a Program: `out[0] = all(values[i] != 0)`.
///
/// The accumulation uses `atomic_and` against `out[0]` directly,
/// initialising the slot to the And-identity (`1`) on entry. The
/// rationale matches `reduce_any`: the lowered IR carries an
/// `AtomicOp::And` node downstream passes can detect, and the
/// pattern stays correct if a future caller fans the dispatch across
/// multiple workgroups.
#[must_use]
pub fn reduce_all(values: &str, out: &str, count: u32) -> Program {
    let body = vec![
        Node::store(out, Expr::u32(0), Expr::u32(1)),
        Node::loop_for(
            "i",
            Expr::u32(0),
            Expr::u32(count),
            vec![
                Node::let_bind("v", Expr::load(values, Expr::var("i"))),
                Node::let_bind(
                    "_acc_prev",
                    Expr::atomic_and(
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
    if values.iter().all(|&value| value != 0) {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_is_true_when_every_lane_is_non_zero() {
        assert_eq!(cpu_ref(&[1, 7, 9]), 1);
    }

    #[test]
    fn all_is_false_when_any_lane_is_zero() {
        assert_eq!(cpu_ref(&[1, 0, 9]), 0);
    }
}
