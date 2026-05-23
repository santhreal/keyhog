//! `bitset_not` — per-word bitwise NOT over a packed bitset.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::bitset::not";

/// Build a Program: `out[w] = !input[w]`.
#[must_use]
pub fn bitset_not(input: &str, out: &str, words: u32) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let body = vec![Node::store(
        out,
        t.clone(),
        Expr::UnOp {
            op: UnOp::BitNot,
            operand: Box::new(Expr::load(input, t.clone())),
        },
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32).with_count(words),
            BufferDecl::storage(out, 1, BufferAccess::ReadWrite, DataType::U32).with_count(words),
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

/// CPU reference.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref(input: &[u32]) -> Vec<u32> {
    let mut out = Vec::new();
    cpu_ref_into(input, &mut out);
    out
}

/// CPU reference into caller-owned storage.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref_into(input: &[u32], out: &mut Vec<u32>) {
    out.clear();
    out.reserve(input.len());
    out.extend(input.iter().map(|word| !word));
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || bitset_not("input", "out", 1),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0x0F0F_0F0F]), to_bytes(&[0])]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0xF0F0_F0F0])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flips_every_bit() {
        assert_eq!(cpu_ref(&[0x0F0F_0F0F]), vec![0xF0F0_F0F0]);
    }

    #[test]
    fn empty_bitset() {
        assert_eq!(cpu_ref(&[]), Vec::<u32>::new());
    }

    #[test]
    fn single_word_all_bits() {
        assert_eq!(cpu_ref(&[0xFFFF_FFFF]), vec![0x0000_0000]);
        assert_eq!(cpu_ref(&[0x0000_0000]), vec![0xFFFF_FFFF]);
    }

    #[test]
    fn cross_word_boundary() {
        let input = vec![0x8000_0000, 0x0000_0001];
        assert_eq!(cpu_ref(&input), vec![0x7FFF_FFFF, 0xFFFF_FFFE]);
    }
}
