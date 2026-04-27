//! Cat-A `fnv1a64` — FNV-1a 64-bit hash.
//!
//! Reference spec:
//! ```text
//! hash = FNV_OFFSET_BASIS_64;       // 0xCBF29CE484222325
//! for byte in data:
//!     hash = (hash XOR byte) * FNV_PRIME_64;  // 0x00000100000001B3
//! ```
//!
//! The IR lacks native u64 arithmetic. We emulate u64 state as a
//! `(lo, hi)` u32 pair and perform the widening multiply by pieces.
//! Because the FNV prime is `(p_hi << 32) | p_lo` with
//! `p_lo = 0x01B3 < 2^16` and `p_hi = 0x0100 < 2^16`, every
//! sub-product `(u32) × (u32<2^16)` fits back in a u32 after
//! appropriate shifts. The widening multiply decomposes:
//!
//! ```text
//! result_lo = (h_lo * p_lo) mod 2^32
//! carry     = high-32-bits of the true (h_lo * p_lo)  // < 2^16
//! result_hi = (h_hi * p_lo + h_lo * p_hi + carry) mod 2^32
//! ```
//!
//! `carry` is computed by splitting `h_lo` into 16-bit halves.
//!
//! Output: two u32 slots, `out[0] = result_lo`, `out[1] = result_hi`.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Program};
use vyre_foundation::ir::model::expr::GeneratorRef;
use vyre_primitives::hash::fnv1a::{fnv1a64_program, FNV1A64_OP_ID};

#[cfg(test)]
use crate::buffer_names::fixed_name;
use crate::buffer_names::scoped_generic_name;

const OP_ID: &str = "vyre-libs::hash::fnv1a64";
const FAMILY_PREFIX: &str = "hash_fnv1a64";

fn scoped_input_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "input", name, &["input"])
}

fn scoped_output_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "out", name, &["out", "output"])
}

/// Build a Program that writes FNV-1a-64(input[0..]) as two u32
/// halves (low, high) to `out[0]` and `out[1]`.
#[must_use]
pub fn fnv1a64(input: &str, out: &str) -> Program {
    let input = scoped_input_buffer(input);
    let out = scoped_output_buffer(out);
    let primitive = fnv1a64_program(&input, &out);
    let parent = GeneratorRef {
        name: OP_ID.to_string(),
    };
    Program::wrapped(
        vec![
            BufferDecl::storage(&input, 0, BufferAccess::ReadOnly, DataType::U32),
            BufferDecl::output(&out, 1, DataType::U32).with_count(2),
        ],
        primitive.workgroup_size(),
        vec![crate::region::wrap_anonymous(
            OP_ID,
            vec![crate::region::wrap_child(
                FNV1A64_OP_ID,
                parent,
                primitive.entry().to_vec(),
            )],
        )],
    )
}

#[cfg(test)]
fn cpu_ref_u64(input: &[u8]) -> u64 {
    const P: u64 = 1_099_511_628_211;
    const INIT: u64 = 14_695_981_039_346_656_037;
    let mut h = INIT;
    for &b in input {
        h ^= u64::from(b);
        h = h.wrapping_mul(P);
    }
    h
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || fnv1a64("input", "out"),
        test_inputs: Some(|| {
            let mut bytes = Vec::with_capacity(12);
            for &b in b"abc" { bytes.extend_from_slice(&u32::from(b).to_le_bytes()); }
            vec![vec![bytes, vec![0u8; 8]]]
        }),
        // FNV-1a 64("abc") = 0xe71fa2190541574b (canonical test vector).
        // Written LE as [lo, hi] pair of u32s.
        expected_output: Some(|| {
            let hash: u64 = 0xe71f_a219_0541_574bu64;
            let bytes = hash.to_le_bytes().to_vec();
            vec![vec![bytes]]
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::pack_bytes_as_u32;
    use vyre_reference::value::Value;

    fn run(bytes: &[u8]) -> u64 {
        let program = fnv1a64("input", "out");
        let inputs = vec![
            Value::Bytes(pack_bytes_as_u32(bytes).into()),
            Value::Bytes(vec![0u8; 8].into()),
        ];
        let outputs = vyre_reference::reference_eval(&program, &inputs).expect("fnv1a64 must run");
        let raw = outputs[0].to_bytes();
        let lo = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let hi = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
        (u64::from(hi) << 32) | u64::from(lo)
    }

    #[test]
    fn abc_matches_ref() {
        assert_eq!(run(b"abc"), cpu_ref_u64(b"abc"));
    }

    #[test]
    fn foobar_matches_known_vector() {
        assert_eq!(run(b"foobar"), 0x8594_4171_F739_67E8);
    }

    #[test]
    fn random_64_bytes_match_ref() {
        let bytes: Vec<u8> = (0u8..64).collect();
        assert_eq!(run(&bytes), cpu_ref_u64(&bytes));
    }

    #[test]
    fn random_512_bytes_match_ref() {
        // Stress the widening-multiply carry logic.
        let mut x: u32 = 0xDEAD_BEEF;
        let bytes: Vec<u8> = (0..512)
            .map(|_| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (x >> 24) as u8
            })
            .collect();
        assert_eq!(run(&bytes), cpu_ref_u64(&bytes));
    }

    #[test]
    fn generic_default_names_are_family_scoped() {
        let program = fnv1a64("input", "out");
        assert_eq!(
            program.buffers()[0].name(),
            fixed_name(FAMILY_PREFIX, "input")
        );
        assert_eq!(
            program.buffers()[1].name(),
            fixed_name(FAMILY_PREFIX, "out")
        );
    }
}
