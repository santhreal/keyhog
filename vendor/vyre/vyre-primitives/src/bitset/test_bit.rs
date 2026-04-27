//! `bitset_test_bit` — scalar query: write 1 to `out_scalar` iff
//! the bit at `bit_idx` of `buf` is set, else 0.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::bitset::test_bit";

/// Build a Program: `out_scalar[0] = (buf[bit_idx/32] >> (bit_idx%32)) & 1`.
#[must_use]
pub fn bitset_test_bit(buf: &str, bit_idx: u32, out_scalar: &str) -> Program {
    let word = bit_idx / 32;
    let bit = bit_idx % 32;
    let body = vec![Node::store(
        out_scalar,
        Expr::u32(0),
        Expr::bitand(
            Expr::shr(Expr::load(buf, Expr::u32(word)), Expr::u32(bit)),
            Expr::u32(1),
        ),
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(buf, 0, BufferAccess::ReadOnly, DataType::U32),
            BufferDecl::storage(out_scalar, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
        ],
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference.
#[must_use]
pub fn cpu_ref(buf: &[u32], bit_idx: u32) -> u32 {
    let w = (bit_idx / 32) as usize;
    let b = bit_idx % 32;
    if w >= buf.len() {
        0
    } else {
        (buf[w] >> b) & 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_set_returns_one() {
        assert_eq!(cpu_ref(&[0b1010], 1), 1);
        assert_eq!(cpu_ref(&[0b1010], 3), 1);
    }

    #[test]
    fn bit_unset_returns_zero() {
        assert_eq!(cpu_ref(&[0b1010], 0), 0);
        assert_eq!(cpu_ref(&[0b1010], 2), 0);
    }

    #[test]
    fn out_of_range_returns_zero() {
        assert_eq!(cpu_ref(&[0xFFFF_FFFF], 1024), 0);
    }

    #[test]
    fn bit_in_second_word() {
        assert_eq!(cpu_ref(&[0, 0b100], 34), 1);
    }
}
