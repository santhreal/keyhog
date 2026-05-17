//! Stochastic computing primitive (#59, research scaffold).
//!
//! Stochastic computing (Gaines 1969, Alaghi 2018 revival) represents
//! numbers as bitstreams; multiplication = AND, addition = MUX.
//! Trades precision for power efficiency. Recent NN inference work
//! (Tehrani 2023) uses it on GPU as bitset operations.
//!
//! This file ships **stochastic-AND multiplication** — multiply two
//! bitstream representations elementwise.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Op id.
pub const OP_ID: &str = "vyre-primitives::bitset::stochastic_and_mul";

/// Stochastic multiply (AND of bitstreams).
#[must_use]
pub fn stochastic_and_mul(a: &str, b: &str, out: &str, n_words: u32) -> Program {
    if n_words == 0 {
        return crate::invalid_output_program(
            OP_ID,
            out,
            DataType::U32,
            "Fix: stochastic_and_mul requires n_words > 0, got 0.".to_string(),
        );
    }

    let t = Expr::InvocationId { axis: 0 };
    let value = Expr::bitand(Expr::load(a, t.clone()), Expr::load(b, t.clone()));

    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(n_words)),
        vec![Node::store(out, t, value)],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(a, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n_words),
            BufferDecl::storage(b, 1, BufferAccess::ReadOnly, DataType::U32).with_count(n_words),
            BufferDecl::storage(out, 2, BufferAccess::ReadWrite, DataType::U32).with_count(n_words),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU helper: encode `p ∈ [0, 1]` as bitstream of length `len_bits`.
#[must_use]
pub fn encode_bitstream(p: f64, len_bits: usize, seed: u32) -> Vec<u32> {
    let mut out = Vec::new();
    encode_bitstream_into(p, len_bits, seed, &mut out);
    out
}

/// CPU helper: encode into a caller-owned bitstream buffer.
pub fn encode_bitstream_into(p: f64, len_bits: usize, seed: u32, out: &mut Vec<u32>) {
    let n_words = (len_bits + 31) / 32;
    out.clear();
    out.resize(n_words, 0);
    let mut state = seed.max(1);
    let threshold = (p.clamp(0.0, 1.0) * (u32::MAX as f64)) as u32;
    for i in 0..len_bits {
        // xorshift32 for cheap deterministic pseudo-random
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        if state < threshold {
            out[i / 32] |= 1 << (i % 32);
        }
    }
}

/// CPU helper: decode bitstream to `p ∈ [0, 1]` by counting set bits.
#[must_use]
pub fn decode_bitstream(bs: &[u32], len_bits: usize) -> f64 {
    let count: u32 = bs.iter().map(|w| w.count_ones()).sum();
    let count = count.min(len_bits as u32);
    count as f64 / len_bits as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_encode_decode_roundtrip_low_p() {
        let bs = encode_bitstream(0.25, 1024, 42);
        let p = decode_bitstream(&bs, 1024);
        assert!((p - 0.25).abs() < 0.05);
    }

    #[test]
    fn cpu_encode_decode_roundtrip_high_p() {
        let bs = encode_bitstream(0.75, 1024, 42);
        let p = decode_bitstream(&bs, 1024);
        assert!((p - 0.75).abs() < 0.05);
    }

    #[test]
    fn encode_bitstream_into_reuses_output() {
        let mut bs = Vec::with_capacity(64);
        let ptr = bs.as_ptr();
        encode_bitstream_into(0.25, 1024, 42, &mut bs);
        assert!((decode_bitstream(&bs, 1024) - 0.25).abs() < 0.05);
        assert_eq!(bs.as_ptr(), ptr);
    }

    #[test]
    fn cpu_zero_p_yields_zero_bitstream() {
        let bs = encode_bitstream(0.0, 256, 1);
        for w in bs {
            assert_eq!(w, 0);
        }
    }

    #[test]
    fn ir_program_buffer_layout() {
        let p = stochastic_and_mul("a", "b", "out", 8);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        for buf in p.buffers.iter() {
            assert_eq!(buf.count(), 8);
        }
    }

    #[test]
    fn zero_n_words_traps() {
        let p = stochastic_and_mul("a", "b", "out", 0);
        assert!(p.stats().trap());
    }
}
