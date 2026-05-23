//! CRC-32 (IEEE 802.3) hash primitive.
//!
//! Polynomial `0xEDB88320` — the reflected form of `0x04C11DB7`, the
//! one used by gzip, zip, Ethernet, PNG, rsync. Byte-at-a-time
//! table-driven. Reference implementation is a straight port of the
//! textbook slicing algorithm.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical CRC-32 initial value.
pub const CRC32_INIT: u32 = 0xFFFF_FFFF;

/// Reflected IEEE 802.3 polynomial.
pub const CRC32_POLY: u32 = 0xEDB8_8320;

/// Stable Tier 2.5 op id for the CRC-32 serial byte walker.
pub const CRC32_OP_ID: &str = "vyre-primitives::hash::crc32";

/// CPU reference: CRC-32 over a byte slice. Returns the post-complement
/// value (matches the gzip / zip convention).
#[must_use]
pub fn crc32(bytes: &[u8]) -> u32 {
    let table = build_table();
    let mut crc = CRC32_INIT;
    for &byte in bytes {
        let idx = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    crc ^ CRC32_INIT
}

/// Build the 256-entry CRC-32 table at runtime. Deterministic; the
/// GPU-side op loads this buffer from the host.
#[must_use]
pub fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 == 1 {
                (c >> 1) ^ CRC32_POLY
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    table
}

/// Build a Program that writes CRC-32(input[0..n]) to `out[0]`.
///
/// `input[i]` packs one byte per u32 slot in the low 8 bits; high bits are
/// ignored by construction. This is the single source of truth for the CRC-32
/// executable IR body; higher-tier wrappers may rename buffers or stamp their
/// own region id, but must delegate to this primitive body instead of forking
/// the bit loop.
#[must_use]
pub fn crc32_program(input: &str, out: &str, n: u32) -> Program {
    let body = vec![Node::Region {
        generator: Ident::from(CRC32_OP_ID),
        source_region: None,
        body: Arc::new(crc32_body(input, out, n)),
    }];
    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::output(out, 1, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        body,
    )
}

fn crc32_body(input: &str, out: &str, n: u32) -> Vec<Node> {
    vec![Node::if_then(
        Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
        vec![
            Node::let_bind("crc", Expr::u32(CRC32_INIT)),
            Node::loop_for(
                "i",
                Expr::u32(0),
                Expr::u32(n),
                vec![
                    Node::assign(
                        "crc",
                        Expr::bitxor(
                            Expr::var("crc"),
                            Expr::bitand(Expr::load(input, Expr::var("i")), Expr::u32(0xFF)),
                        ),
                    ),
                    Node::loop_for(
                        "bit",
                        Expr::u32(0),
                        Expr::u32(8),
                        vec![Node::assign(
                            "crc",
                            Expr::Select {
                                cond: Box::new(Expr::ne(
                                    Expr::bitand(Expr::var("crc"), Expr::u32(1)),
                                    Expr::u32(0),
                                )),
                                true_val: Box::new(Expr::bitxor(
                                    Expr::shr(Expr::var("crc"), Expr::u32(1)),
                                    Expr::u32(CRC32_POLY),
                                )),
                                false_val: Box::new(Expr::shr(Expr::var("crc"), Expr::u32(1))),
                            },
                        )],
                    ),
                ],
            ),
            Node::store(
                out,
                Expr::u32(0),
                Expr::bitxor(Expr::var("crc"), Expr::u32(CRC32_INIT)),
            ),
        ],
    )]
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        CRC32_OP_ID,
        || crc32_program("input", "out", 3),
        Some(|| {
            let mut bytes = Vec::with_capacity(12);
            for &byte in b"abc" {
                bytes.extend_from_slice(&u32::from(byte).to_le_bytes());
            }
            vec![vec![bytes, vec![0u8; 4]]]
        }),
        Some(|| vec![vec![0x3524_41c2u32.to_le_bytes().to_vec()]]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference vectors from RFC 3720 (iSCSI) + the Castagnoli paper.

    #[test]
    fn crc32_empty_is_zero() {
        // CRC-32("" ) = 0 after the final complement.
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn crc32_single_zero_byte() {
        // crc32([0x00]) = 0xD202_EF8D
        assert_eq!(crc32(&[0x00]), 0xD202_EF8D);
    }

    #[test]
    fn crc32_nine_ones() {
        // crc32("123456789") = 0xCBF4_3926 — classic test vector.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn crc32_table_128_slot() {
        // First row after zero should be 1→polynomial-shift.
        let table = build_table();
        assert_eq!(table[0], 0);
        // Standard table[1] for 0xEDB88320.
        assert_eq!(table[1], 0x7707_3096);
    }

    #[test]
    fn crc32_program_is_single_primitive_region() {
        let program = crc32_program("input", "out", 3);
        assert_eq!(program.entry().len(), 1);
        match &program.entry()[0] {
            Node::Region { generator, .. } => assert_eq!(generator.as_str(), CRC32_OP_ID),
            other => panic!("expected primitive CRC32 region, got {other:?}"),
        }
    }
}
