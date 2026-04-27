//! `bitset_set_bit` — scalar mutate: set bit `bit_idx` in `target`.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::bitset::set_bit";

/// Build a Program: `target[bit_idx/32] |= 1 << (bit_idx%32)`.
#[must_use]
pub fn bitset_set_bit(target: &str, bit_idx: u32, words: u32) -> Program {
    let word = bit_idx / 32;
    let bit = bit_idx % 32;
    let body = vec![Node::store(
        target,
        Expr::u32(word),
        Expr::bitor(
            Expr::load(target, Expr::u32(word)),
            Expr::shl(Expr::u32(1), Expr::u32(bit)),
        ),
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(target, 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(words),
        ],
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference. Mutates `target` in place.
pub fn cpu_ref(target: &mut [u32], bit_idx: u32) {
    let w = (bit_idx / 32) as usize;
    let b = bit_idx % 32;
    if w < target.len() {
        target[w] |= 1u32 << b;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets_low_bit() {
        let mut buf = vec![0u32];
        cpu_ref(&mut buf, 0);
        assert_eq!(buf, vec![1]);
    }

    #[test]
    fn sets_bit_in_second_word() {
        let mut buf = vec![0u32, 0u32];
        cpu_ref(&mut buf, 34);
        assert_eq!(buf, vec![0, 0b100]);
    }

    #[test]
    fn idempotent_on_already_set() {
        let mut buf = vec![0b1010u32];
        cpu_ref(&mut buf, 1);
        assert_eq!(buf, vec![0b1010]);
    }

    #[test]
    fn out_of_range_is_noop() {
        let mut buf = vec![0u32];
        cpu_ref(&mut buf, 1024);
        assert_eq!(buf, vec![0]);
    }
}
