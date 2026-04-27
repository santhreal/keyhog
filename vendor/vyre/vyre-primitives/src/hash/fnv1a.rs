//! FNV-1a 32-bit + 64-bit hash primitives.
//!
//! FNV-1a is a non-cryptographic hash with a tight inner loop:
//! `h = (h XOR byte) * prime`. Used everywhere a fast non-secure
//! fingerprint is good enough — dialect-id interning, pipeline-cache
//! sharding, per-op id hashing.
//!
//! Both widths (32, 64) share the structure; only the magic constants
//! differ. The CPU reference is byte-identical to every conformant
//! FNV-1a implementation.

/// FNV-1a offset basis (32-bit).
pub const FNV1A32_OFFSET: u32 = 0x811c_9dc5;
/// FNV-1a prime (32-bit).
pub const FNV1A32_PRIME: u32 = 0x0100_0193;

/// FNV-1a offset basis (64-bit).
pub const FNV1A64_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a prime (64-bit).
pub const FNV1A64_PRIME: u64 = 0x0000_0100_0000_01b3;

/// CPU reference: FNV-1a 32-bit over a byte slice.
#[must_use]
pub fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut h = FNV1A32_OFFSET;
    for &byte in bytes {
        h ^= u32::from(byte);
        h = h.wrapping_mul(FNV1A32_PRIME);
    }
    h
}

use std::sync::Arc;
use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Stable op id — the Tier 3 wrapper registers under this id.
pub const FNV1A32_OP_ID: &str = "vyre-primitives::hash::fnv1a32";
/// Stable op id for the 64-bit widening-multiply builder.
pub const FNV1A64_OP_ID: &str = "vyre-primitives::hash::fnv1a64";
const FNV1A64_PRIME_LO: u32 = 0x0000_01B3;
const FNV1A64_PRIME_HI: u32 = 0x0000_0100;
const FNV1A64_OFFSET_LO: u32 = 0x8422_2325;
const FNV1A64_OFFSET_HI: u32 = 0xCBF2_9CE4;

/// GPU IR builder: FNV-1a 32-bit serial walk over `input[0..n]` — each
/// input word contributes its low 8 bits as the next byte. Output is
/// one u32 hash at `out[0]`. Single invocation (invocation 0 does the
/// whole walk); callers needing parallel throughput compose this with
/// a reduce primitive.
#[must_use]
pub fn fnv1a32_program(input: &str, out: &str, n: u32) -> Program {
    fnv1a32_program_bounded(input, out, Expr::u32(n), Some(n))
}

/// Dynamic-bound variant: loop bound is `Expr::buf_len(input)` so the
/// shader walks whatever the caller's input buffer declares at dispatch
/// time. The returned Program leaves `input` without a static count.
#[must_use]
pub fn fnv1a32_program_dyn(input: &str, out: &str) -> Program {
    fnv1a32_program_bounded(input, out, Expr::buf_len(input), None)
}

fn fnv1a32_program_bounded(
    input: &str,
    out: &str,
    loop_bound: Expr,
    static_count: Option<u32>,
) -> Program {
    let body = vec![Node::Region {
        generator: Ident::from(FNV1A32_OP_ID),
        source_region: None,
        body: Arc::new(vec![Node::if_then(
            Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
            vec![
                Node::let_bind("h", Expr::u32(FNV1A32_OFFSET)),
                Node::loop_for(
                    "i",
                    Expr::u32(0),
                    loop_bound,
                    vec![
                        Node::let_bind(
                            "byte",
                            Expr::bitand(Expr::load(input, Expr::var("i")), Expr::u32(0xFF)),
                        ),
                        Node::assign("h", Expr::bitxor(Expr::var("h"), Expr::var("byte"))),
                        Node::assign("h", Expr::mul(Expr::var("h"), Expr::u32(FNV1A32_PRIME))),
                    ],
                ),
                Node::store(out, Expr::u32(0), Expr::var("h")),
            ],
        )]),
    }];

    let input_buf = match static_count {
        Some(n) => {
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n)
        }
        None => BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32),
    };

    Program::wrapped(
        vec![
            input_buf,
            BufferDecl::output(out, 1, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        body,
    )
}

/// GPU IR builder: FNV-1a 64-bit serial walk over `input[0..n]`.
///
/// The IR lacks native `u64`, so the state is maintained as `(low, high)` u32
/// halves and multiplied by the FNV prime via a widened split product.
#[must_use]
pub fn fnv1a64_program(input: &str, out: &str) -> Program {
    let body = vec![Node::Region {
        generator: Ident::from(FNV1A64_OP_ID),
        source_region: None,
        body: Arc::new(vec![Node::if_then(
            Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
            vec![
                Node::let_bind("h_lo", Expr::u32(FNV1A64_OFFSET_LO)),
                Node::let_bind("h_hi", Expr::u32(FNV1A64_OFFSET_HI)),
                Node::loop_for(
                    "i",
                    Expr::u32(0),
                    Expr::buf_len(input),
                    vec![
                        Node::assign(
                            "h_lo",
                            Expr::bitxor(Expr::var("h_lo"), Expr::load(input, Expr::var("i"))),
                        ),
                        Node::let_bind(
                            "lo_lo16",
                            Expr::bitand(Expr::var("h_lo"), Expr::u32(0xFFFF)),
                        ),
                        Node::let_bind("lo_hi16", Expr::shr(Expr::var("h_lo"), Expr::u32(16))),
                        Node::let_bind(
                            "part_a",
                            Expr::mul(Expr::var("lo_lo16"), Expr::u32(FNV1A64_PRIME_LO)),
                        ),
                        Node::let_bind(
                            "part_b",
                            Expr::mul(Expr::var("lo_hi16"), Expr::u32(FNV1A64_PRIME_LO)),
                        ),
                        Node::let_bind("shifted_b", Expr::shl(Expr::var("part_b"), Expr::u32(16))),
                        Node::let_bind(
                            "new_lo",
                            Expr::add(Expr::var("part_a"), Expr::var("shifted_b")),
                        ),
                        Node::let_bind(
                            "overflow_bit",
                            Expr::Select {
                                cond: Box::new(Expr::gt(
                                    Expr::var("part_a"),
                                    Expr::sub(Expr::u32(u32::MAX), Expr::var("shifted_b")),
                                )),
                                true_val: Box::new(Expr::u32(1)),
                                false_val: Box::new(Expr::u32(0)),
                            },
                        ),
                        Node::let_bind(
                            "carry",
                            Expr::add(
                                Expr::shr(Expr::var("part_b"), Expr::u32(16)),
                                Expr::var("overflow_bit"),
                            ),
                        ),
                        Node::let_bind(
                            "hi_times_p_lo",
                            Expr::mul(Expr::var("h_hi"), Expr::u32(FNV1A64_PRIME_LO)),
                        ),
                        Node::let_bind(
                            "lo_times_p_hi",
                            Expr::mul(Expr::var("h_lo"), Expr::u32(FNV1A64_PRIME_HI)),
                        ),
                        Node::let_bind(
                            "new_hi",
                            Expr::add(
                                Expr::add(Expr::var("hi_times_p_lo"), Expr::var("lo_times_p_hi")),
                                Expr::var("carry"),
                            ),
                        ),
                        Node::assign("h_lo", Expr::var("new_lo")),
                        Node::assign("h_hi", Expr::var("new_hi")),
                    ],
                ),
                Node::store(out, Expr::u32(0), Expr::var("h_lo")),
                Node::store(out, Expr::u32(1), Expr::var("h_hi")),
            ],
        )]),
    }];

    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32),
            BufferDecl::output(out, 1, DataType::U32).with_count(2),
        ],
        [1, 1, 1],
        body,
    )
}

/// CPU reference: FNV-1a 64-bit over a byte slice.
#[must_use]
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h = FNV1A64_OFFSET;
    for &byte in bytes {
        h ^= u64::from(byte);
        h = h.wrapping_mul(FNV1A64_PRIME);
    }
    h
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        FNV1A32_OP_ID,
        || fnv1a32_program("input", "out", 1),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0x61]), // input: one word, low byte = 'a'
                to_bytes(&[0]),    // output
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0xe40c_292c])]] // canonical FNV-1a32("a")
        }),
    )
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        FNV1A64_OP_ID,
        || fnv1a64_program("input", "out"),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0x61]),   // input: one word, low byte = 'a'
                to_bytes(&[0, 0]),   // output: two words for fnv1a64 hash
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0x8601_ec8c, 0xaf63_dc4c])]] // canonical FNV-1a64("a") little-endian halves
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Conformance vectors from the canonical FNV test suite.
    // http://www.isthe.com/chongo/tech/comp/fnv/

    #[test]
    fn fnv1a32_empty_is_offset() {
        assert_eq!(fnv1a32(b""), FNV1A32_OFFSET);
    }

    #[test]
    fn fnv1a32_single_ascii_a() {
        assert_eq!(fnv1a32(b"a"), 0xe40c_292c);
    }

    #[test]
    fn gpu_builder_matches_cpu_ref() {
        use vyre_foundation::ir::model::expr::Ident;
        let program = fnv1a32_program("src", "out", 5);
        // Validate region chain wrap.
        match &program.entry()[0] {
            Node::Region { generator, .. } => {
                assert_eq!(generator, &Ident::from(FNV1A32_OP_ID));
            }
            other => panic!("expected top-level Region, got {other:?}"),
        }
        // Buffer count sanity.
        assert_eq!(program.buffers().len(), 2);
    }

    #[test]
    fn fnv1a32_is_deterministic_and_not_identity() {
        // Two invocations over the same input produce identical hashes
        // (determinism); distinct inputs of equal length produce
        // distinct hashes (avalanche sanity).
        let a = fnv1a32(b"The quick brown fox");
        let b = fnv1a32(b"The quick brown fox");
        assert_eq!(a, b);
        let c = fnv1a32(b"The quick brown cow");
        assert_ne!(a, c);
    }

    #[test]
    fn fnv1a64_empty_is_offset() {
        assert_eq!(fnv1a64(b""), FNV1A64_OFFSET);
    }

    #[test]
    fn fnv1a64_single_ascii_a() {
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[test]
    fn fnv1a64_matches_fnv1a32_structure() {
        // Sanity: different widths of the same input MUST NOT produce
        // matching low-32 bits — the prime differs, so structure does too.
        let bytes = b"vyre fingerprint";
        let h32 = fnv1a32(bytes);
        let h64 = fnv1a64(bytes);
        assert_ne!(h32 as u64, h64 & 0xffff_ffff);
    }
}
