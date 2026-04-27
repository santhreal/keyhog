//! `bitset_any` — emit 1 when any bit in the packed bitset is set.
//!
//! Single-lane Program driven by invocation 0: scans every word,
//! ORs them, writes a boolean (0 or 1) to `out[0]`. Used by SURGE
//! `exists` / `any(...)` aggregate lowerings.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::bitset::any";

/// Build a Program: `out[0] = 1` iff any bit of `input` is set.
///
/// AUDIT_2026-04-24 F-ANY-01: the inner loop short-circuits once a
/// non-zero word is observed (tracked via `found` flag). The IR has
/// no `break`, so the cheapest escape is to gate the load+or body on
/// `found == 0` — subsequent iterations become empty bodies and the
/// scan cost degrades to O(first_nonzero_word) instead of O(words).
/// Bitsets are typically sparse (e.g. taint frontiers with one or
/// two set bits) so the average cut is large.
#[must_use]
pub fn bitset_any(input: &str, out: &str, words: u32) -> Program {
    let body = vec![
        Node::let_bind("acc", Expr::u32(0)),
        Node::let_bind("found", Expr::u32(0)),
        Node::loop_for(
            "w",
            Expr::u32(0),
            Expr::u32(words),
            vec![Node::if_then(
                Expr::eq(Expr::var("found"), Expr::u32(0)),
                vec![
                    Node::assign(
                        "acc",
                        Expr::bitor(Expr::var("acc"), Expr::load(input, Expr::var("w"))),
                    ),
                    Node::if_then(
                        Expr::ne(Expr::var("acc"), Expr::u32(0)),
                        vec![Node::assign("found", Expr::u32(1))],
                    ),
                ],
            )],
        ),
        Node::store(
            out,
            Expr::u32(0),
            Expr::select(
                Expr::ne(Expr::var("acc"), Expr::u32(0)),
                Expr::u32(1),
                Expr::u32(0),
            ),
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32).with_count(words),
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
pub fn cpu_ref(input: &[u32]) -> u32 {
    if input.iter().any(|w| *w != 0) {
        1
    } else {
        0
    }
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || bitset_any("input", "out", 2),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0, 1]), to_bytes(&[0])]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[1])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_true_when_single_bit_set() {
        assert_eq!(cpu_ref(&[0, 1]), 1);
    }

    #[test]
    fn any_false_when_all_zero() {
        assert_eq!(cpu_ref(&[0, 0]), 0);
    }
}
