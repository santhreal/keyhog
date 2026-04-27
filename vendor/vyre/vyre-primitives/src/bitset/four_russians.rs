//! Method-of-Four-Russians byte-tile lookup for packed boolean words.
//!
//! The primitive maps each `(lhs_byte, rhs_byte)` pair through a 65,536-entry
//! table and assembles four looked-up bytes back into one `u32`. Higher-level
//! boolean-matrix and reachability kernels can specialize the LUT once, then
//! replace branchy byte logic with coalesced table loads.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::bitset::four_russians_apply_byte_lut";

/// Binary boolean operation encoded into a byte-pair LUT.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BooleanTileOp {
    /// `lhs & rhs`
    And,
    /// `lhs | rhs`
    Or,
    /// `lhs ^ rhs`
    Xor,
    /// `lhs & !rhs`
    AndNot,
}

impl BooleanTileOp {
    const fn apply(self, lhs: u8, rhs: u8) -> u8 {
        match self {
            Self::And => lhs & rhs,
            Self::Or => lhs | rhs,
            Self::Xor => lhs ^ rhs,
            Self::AndNot => lhs & !rhs,
        }
    }
}

/// Build a 65,536-entry LUT indexed by `(lhs_byte << 8) | rhs_byte`.
#[must_use]
pub fn binary_byte_lut(op: BooleanTileOp) -> Vec<u32> {
    let mut table = vec![0u32; 256 * 256];
    for lhs in 0u32..=255 {
        for rhs in 0u32..=255 {
            let idx = ((lhs << 8) | rhs) as usize;
            table[idx] = u32::from(op.apply(lhs as u8, rhs as u8));
        }
    }
    table
}

/// Build a Program: `out[w] = lut[(lhs_byte << 8) | rhs_byte]` per byte lane.
#[must_use]
pub fn four_russians_apply_byte_lut(
    lhs: &str,
    rhs: &str,
    lut: &str,
    out: &str,
    words: u32,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let mut body = vec![
        Node::let_bind("fr_lhs_word", Expr::load(lhs, t.clone())),
        Node::let_bind("fr_rhs_word", Expr::load(rhs, t.clone())),
        Node::let_bind("fr_out_word", Expr::u32(0)),
    ];
    body.push(Node::loop_for(
        "fr_byte_lane",
        Expr::u32(0),
        Expr::u32(4),
        vec![
            Node::let_bind(
                "fr_shift",
                Expr::mul(Expr::var("fr_byte_lane"), Expr::u32(8)),
            ),
            Node::let_bind(
                "fr_lhs_byte",
                Expr::bitand(
                    Expr::shr(Expr::var("fr_lhs_word"), Expr::var("fr_shift")),
                    Expr::u32(0xFF),
                ),
            ),
            Node::let_bind(
                "fr_rhs_byte",
                Expr::bitand(
                    Expr::shr(Expr::var("fr_rhs_word"), Expr::var("fr_shift")),
                    Expr::u32(0xFF),
                ),
            ),
            Node::let_bind(
                "fr_lut_idx",
                Expr::bitor(
                    Expr::shl(Expr::var("fr_lhs_byte"), Expr::u32(8)),
                    Expr::var("fr_rhs_byte"),
                ),
            ),
            Node::let_bind(
                "fr_byte_out",
                Expr::bitand(Expr::load(lut, Expr::var("fr_lut_idx")), Expr::u32(0xFF)),
            ),
            Node::assign(
                "fr_out_word",
                Expr::bitor(
                    Expr::var("fr_out_word"),
                    Expr::shl(Expr::var("fr_byte_out"), Expr::var("fr_shift")),
                ),
            ),
        ],
    ));
    body.push(Node::store(out, t.clone(), Expr::var("fr_out_word")));

    Program::wrapped(
        vec![
            BufferDecl::storage(lhs, 0, BufferAccess::ReadOnly, DataType::U32).with_count(words),
            BufferDecl::storage(rhs, 1, BufferAccess::ReadOnly, DataType::U32).with_count(words),
            BufferDecl::storage(lut, 2, BufferAccess::ReadOnly, DataType::U32).with_count(65_536),
            BufferDecl::storage(out, 3, BufferAccess::ReadWrite, DataType::U32).with_count(words),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::lt(t.clone(), Expr::u32(words)),
                body,
            )]),
        }],
    )
}

/// CPU reference for [`four_russians_apply_byte_lut`].
#[must_use]
pub fn cpu_ref(lhs: &[u32], rhs: &[u32], lut: &[u32]) -> Vec<u32> {
    lhs.iter()
        .zip(rhs.iter())
        .map(|(left, right)| {
            let mut out = 0u32;
            for lane in 0..4 {
                let shift = lane * 8;
                let left_byte = (left >> shift) & 0xFF;
                let right_byte = (right >> shift) & 0xFF;
                let idx = ((left_byte << 8) | right_byte) as usize;
                let byte = lut.get(idx).copied().unwrap_or_default() & 0xFF;
                out |= byte << shift;
            }
            out
        })
        .collect()
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || four_russians_apply_byte_lut("lhs", "rhs", "lut", "out", 2),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0xFF00_FF00, 0x0F0F_0F0F]),
                to_bytes(&[0xF0F0_F0F0, 0xFFFF_0000]),
                to_bytes(&binary_byte_lut(BooleanTileOp::And)),
                to_bytes(&[0, 0]),
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0xF000_F000, 0x0F0F_0000])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_lut_matches_word_and() {
        let lhs = [0xFF00_FF00u32, 0x0F0F_0F0F];
        let rhs = [0xF0F0_F0F0u32, 0xFFFF_0000];
        let lut = binary_byte_lut(BooleanTileOp::And);
        assert_eq!(cpu_ref(&lhs, &rhs, &lut), vec![0xF000_F000, 0x0F0F_0000]);
    }
}
