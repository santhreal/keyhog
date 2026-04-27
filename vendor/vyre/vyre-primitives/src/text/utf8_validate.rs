//! Tier 2.5 UTF-8 validator — single-pass byte-classification scan.
//!
//! Each invocation reads one source byte (`source[i]`, low 8 bits)
//! and writes one of four classification codes into `classes[i]`:
//!
//! - [`UTF8_ASCII`] — byte 0x00..0x7F, single-byte sequence
//! - [`UTF8_LEAD_2`] — byte 0xC0..0xDF, lead of a 2-byte sequence
//! - [`UTF8_LEAD_3`] — byte 0xE0..0xEF, lead of a 3-byte sequence
//! - [`UTF8_LEAD_4`] — byte 0xF0..0xF7, lead of a 4-byte sequence
//! - [`UTF8_CONT`]   — byte 0x80..0xBF, continuation byte
//! - [`UTF8_INVALID`] — byte 0xC0/0xC1 (overlong) or ≥ 0xF8 (out of range)
//!
//! Strict structural validation (continuation-count alignment,
//! surrogate-pair rejection, overlong-encoding detection beyond the
//! initial-byte sanity check) is the responsibility of the caller's
//! follow-up scan that consumes this classification stream. This op
//! provides the raw classification — the LEGO substrate that every
//! parser dialect builds its own UTF-8 enforcement on.

use std::sync::Arc;
use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Stable op id for the registered Tier 3 wrapper.
pub const OP_ID: &str = "vyre-primitives::text::utf8_validate";

/// 0x00..0x7F — single-byte ASCII.
pub const UTF8_ASCII: u32 = 0;
/// 0xC2..0xDF — lead of a valid 2-byte sequence.
pub const UTF8_LEAD_2: u32 = 1;
/// 0xE0..0xEF — lead of a 3-byte sequence.
pub const UTF8_LEAD_3: u32 = 2;
/// 0xF0..0xF7 — lead of a 4-byte sequence.
pub const UTF8_LEAD_4: u32 = 3;
/// 0x80..0xBF — continuation byte.
pub const UTF8_CONT: u32 = 4;
/// 0xC0, 0xC1 (overlong) or 0xF8..0xFF (out of range) — invalid lead.
pub const UTF8_INVALID: u32 = 5;

/// Build a Program that classifies each `source[i]` byte into one of
/// the `UTF8_*` codes above and writes the result into `classes[i]`.
#[must_use]
pub fn utf8_validate(source: &str, classes: &str, n: u32) -> Program {
    let body = vec![Node::Region {
        generator: Ident::from(OP_ID),
        source_region: None,
        body: Arc::new(vec![
            Node::let_bind("idx", Expr::InvocationId { axis: 0 }),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::u32(n)),
                vec![
                    Node::let_bind(
                        "byte",
                        Expr::bitand(Expr::load(source, Expr::var("idx")), Expr::u32(0xFF)),
                    ),
                    // Six-way classification using nested Select. The
                    // ordering walks INVALID first so 0xC0/0xC1 don't
                    // fall through to LEAD_2.
                    Node::let_bind(
                        "class",
                        // ASCII (< 0x80) -> UTF8_ASCII
                        Expr::select(
                            Expr::lt(Expr::var("byte"), Expr::u32(0x80)),
                            Expr::u32(UTF8_ASCII),
                            // CONT (0x80..0xBF) -> UTF8_CONT
                            Expr::select(
                                Expr::lt(Expr::var("byte"), Expr::u32(0xC0)),
                                Expr::u32(UTF8_CONT),
                                // INVALID overlong (0xC0..0xC1) -> UTF8_INVALID
                                Expr::select(
                                    Expr::lt(Expr::var("byte"), Expr::u32(0xC2)),
                                    Expr::u32(UTF8_INVALID),
                                    // LEAD_2 (0xC2..0xDF) -> UTF8_LEAD_2
                                    Expr::select(
                                        Expr::lt(Expr::var("byte"), Expr::u32(0xE0)),
                                        Expr::u32(UTF8_LEAD_2),
                                        // LEAD_3 (0xE0..0xEF) -> UTF8_LEAD_3
                                        Expr::select(
                                            Expr::lt(Expr::var("byte"), Expr::u32(0xF0)),
                                            Expr::u32(UTF8_LEAD_3),
                                            // LEAD_4 (0xF0..0xF7) -> UTF8_LEAD_4
                                            Expr::select(
                                                Expr::lt(Expr::var("byte"), Expr::u32(0xF8)),
                                                Expr::u32(UTF8_LEAD_4),
                                                // 0xF8..0xFF -> UTF8_INVALID
                                                Expr::u32(UTF8_INVALID),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                    Node::store(classes, Expr::var("idx"), Expr::var("class")),
                ],
            ),
        ]),
    }];

    Program::wrapped(
        vec![
            BufferDecl::storage(source, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::output(classes, 1, DataType::U32).with_count(n),
        ],
        [64, 1, 1],
        body,
    )
}

/// CPU reference: classify each byte the same way the GPU kernel does.
#[must_use]
pub fn cpu_ref(source: &[u8]) -> Vec<u32> {
    source
        .iter()
        .map(|&byte| match byte {
            0x00..=0x7F => UTF8_ASCII,
            0x80..=0xBF => UTF8_CONT,
            0xC0 | 0xC1 => UTF8_INVALID,
            0xC2..=0xDF => UTF8_LEAD_2,
            0xE0..=0xEF => UTF8_LEAD_3,
            0xF0..=0xF7 => UTF8_LEAD_4,
            0xF8..=0xFF => UTF8_INVALID,
        })
        .collect()
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || utf8_validate("source", "classes", 8),
        Some(|| {
            vec![vec![
                vec![0xC3, 0x00, 0x00, 0x00, 0xA9, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x00, 0x9F, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00],
                vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            ]]
        }),
        Some(|| {
            vec![vec![
                vec![0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00],
            ]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_ref_ascii() {
        assert_eq!(cpu_ref(b"Hello"), vec![UTF8_ASCII; 5]);
    }

    #[test]
    fn cpu_ref_2_byte_sequence() {
        // U+00E9 (é) = 0xC3 0xA9 — LEAD_2 + CONT
        assert_eq!(cpu_ref(&[0xC3, 0xA9]), vec![UTF8_LEAD_2, UTF8_CONT]);
    }

    #[test]
    fn cpu_ref_3_byte_sequence() {
        // U+20AC (€) = 0xE2 0x82 0xAC — LEAD_3 + CONT + CONT
        assert_eq!(
            cpu_ref(&[0xE2, 0x82, 0xAC]),
            vec![UTF8_LEAD_3, UTF8_CONT, UTF8_CONT]
        );
    }

    #[test]
    fn cpu_ref_4_byte_sequence() {
        // U+1F600 (😀) = 0xF0 0x9F 0x98 0x80 — LEAD_4 + CONT × 3
        assert_eq!(
            cpu_ref(&[0xF0, 0x9F, 0x98, 0x80]),
            vec![UTF8_LEAD_4, UTF8_CONT, UTF8_CONT, UTF8_CONT]
        );
    }

    #[test]
    fn cpu_ref_overlong_lead_invalid() {
        // 0xC0/0xC1 are forbidden lead bytes (overlong 2-byte
        // encodings of ASCII).
        assert_eq!(cpu_ref(&[0xC0, 0xC1]), vec![UTF8_INVALID, UTF8_INVALID]);
    }

    #[test]
    fn cpu_ref_out_of_range_lead_invalid() {
        // 0xF8..0xFF would imply 5+ byte sequences — banned since RFC 3629.
        assert_eq!(
            cpu_ref(&[0xF8, 0xFC, 0xFF]),
            vec![UTF8_INVALID, UTF8_INVALID, UTF8_INVALID]
        );
    }
}
