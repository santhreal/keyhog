//! `reduce_sum` — wrapping unsigned sum over a u32 ValueSet.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::reduce::sum";

const REDUCE_SUM_WORKGROUP_SIZE: u32 = 256;

/// Build a Program: `out[0] = (Σ values_i) mod 2^32`.
#[must_use]
pub fn reduce_sum(values: &str, out: &str, count: u32) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let body = vec![
        Node::if_then(
            Expr::eq(t.clone(), Expr::u32(0)),
            vec![Node::store(out, Expr::u32(0), Expr::u32(0))],
        ),
        Node::Barrier,
        Node::let_bind("grid_size", Expr::u32(REDUCE_SUM_WORKGROUP_SIZE)),
        Node::loop_for(
            "loop_idx",
            Expr::u32(0),
            Expr::div(
                Expr::add(Expr::u32(count), Expr::u32(REDUCE_SUM_WORKGROUP_SIZE - 1)),
                Expr::u32(REDUCE_SUM_WORKGROUP_SIZE),
            ),
            vec![
                Node::let_bind(
                    "i",
                    Expr::add(
                        Expr::mul(Expr::var("loop_idx"), Expr::var("grid_size")),
                        t.clone(),
                    ),
                ),
                Node::if_then(
                    Expr::lt(Expr::var("i"), Expr::u32(count)),
                    vec![Node::let_bind(
                        "_",
                        Expr::atomic_add(out, Expr::u32(0), Expr::load(values, Expr::var("i"))),
                    )],
                ),
            ],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(values, 0, BufferAccess::ReadOnly, DataType::U32).with_count(count),
            BufferDecl::storage(out, 1, BufferAccess::ReadWrite, DataType::U32).with_count(1),
        ],
        [REDUCE_SUM_WORKGROUP_SIZE, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference.
#[must_use]
pub fn cpu_ref(values: &[u32]) -> u32 {
    values.iter().copied().fold(0u32, u32::wrapping_add)
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || reduce_sum("values", "out", 4),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[1, 2, 3, 4]), to_bytes(&[0])]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[10])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_values() {
        assert_eq!(cpu_ref(&[1, 2, 3, 4]), 10);
    }

    #[test]
    fn wraps_on_overflow() {
        assert_eq!(cpu_ref(&[u32::MAX, 1]), 0);
    }

    #[test]
    fn program_uses_parallel_grid_stride() {
        let program = reduce_sum("values", "out", 513);
        assert_eq!(program.workgroup_size(), [REDUCE_SUM_WORKGROUP_SIZE, 1, 1]);
        assert!(
            !format!("{:?}", program.entry()).contains("deferred"),
            "reduce_sum program must not carry deferred grid-size markers"
        );
    }
}
