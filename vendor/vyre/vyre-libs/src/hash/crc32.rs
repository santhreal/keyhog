//! Cat-A `crc32` — CRC-32 (ISO 3309 / ITU-T V.42) checksum.
//!
//! Serial single-invocation walk. Standard CRC-32 polynomial
//! 0xEDB88320 (reflected), init 0xFFFFFFFF, final XOR 0xFFFFFFFF,
//! delegated to the Tier-2.5 primitive so this wrapper owns only naming,
//! provenance, and harness registration.
//!
//! `input[i]` packs one byte per u32 slot (low 8 bits). `out[0]`
//! receives the final CRC-32.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Program};
use vyre_foundation::ir::model::expr::GeneratorRef;
use vyre_primitives::hash::crc32::{crc32_program, CRC32_OP_ID};

#[cfg(test)]
use crate::buffer_names::fixed_name;
use crate::buffer_names::scoped_generic_name;
#[cfg(test)]
use vyre_primitives::hash::crc32::crc32 as crc32_cpu_reference;

const OP_ID: &str = "vyre-libs::hash::crc32";
const FAMILY_PREFIX: &str = "hash_crc32";

fn scoped_input_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "input", name, &["input"])
}

fn scoped_output_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "out", name, &["out", "output"])
}

/// Build a Program that writes CRC-32(input[0..n]) to `out[0]`.
#[must_use]
pub fn crc32(input: &str, out: &str, n: u32) -> Program {
    let input = scoped_input_buffer(input);
    let out = scoped_output_buffer(out);
    let primitive = crc32_program(&input, &out, n);
    let parent = GeneratorRef {
        name: OP_ID.to_string(),
    };
    Program::wrapped(
        vec![
            BufferDecl::storage(&input, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::output(&out, 1, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![crate::region::wrap_anonymous(
            OP_ID,
            vec![crate::region::wrap_child(
                CRC32_OP_ID,
                parent,
                primitive.into_entry_vec(),
            )],
        )],
    )
}

#[cfg(test)]
fn cpu_ref(input: &[u8]) -> u32 {
    crc32_cpu_reference(input)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || crc32("input", "out", 3),
        test_inputs: Some(|| {
            let mut bytes = Vec::with_capacity(12);
            for &b in b"abc" { bytes.extend_from_slice(&u32::from(b).to_le_bytes()); }
            vec![vec![bytes]]
        }),
        // Canonical CRC-32 of "abc" (reflected poly 0xEDB88320) = 0x352441c2.
        expected_output: Some(|| vec![vec![0x352441c2u32.to_le_bytes().to_vec()]]),
        category: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_reference::value::Value;

    fn run(bytes: &[u8]) -> u32 {
        let words = bytes
            .iter()
            .map(|&byte| u32::from(byte))
            .collect::<Vec<_>>();
        run_words(&words)
    }

    fn run_words(words: &[u32]) -> u32 {
        let n = words.len().max(1) as u32;
        let program = crc32("input", "out", n);
        let mut input = Vec::with_capacity(words.len() * 4);
        for &word in words {
            input.extend_from_slice(&word.to_le_bytes());
        }
        let inputs = vec![Value::Bytes(input.into())];
        let outputs = vyre_reference::reference_eval(&program, &inputs)
            .expect("Fix: crc32 must run; restore this invariant before continuing.");
        let raw = outputs[0].to_bytes();
        u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])
    }

    #[test]
    fn abc_matches_ref() {
        assert_eq!(run(b"abc"), 0x352441c2);
        assert_eq!(run(b"abc"), cpu_ref(b"abc"));
    }

    #[test]
    fn canonical_check_value() {
        assert_eq!(run(b"123456789"), 0xcbf43926);
    }

    #[test]
    fn random_64_bytes_match_ref() {
        let bytes: Vec<u8> = (0u8..64).collect();
        assert_eq!(run(&bytes), cpu_ref(&bytes));
    }

    #[test]
    fn high_bits_in_packed_slots_are_ignored() {
        let words = [0xFFFF_FF61, 0xCAFE_0062, 0x8000_0063];
        assert_eq!(run_words(&words), cpu_ref(b"abc"));
    }

    #[test]
    fn wrapper_delegates_to_primitive_crc32_region() {
        let program = crc32("input", "out", 3);
        let [vyre::ir::Node::Region { body, .. }] = program.entry() else {
            panic!("expected one top-level CRC32 wrapper region");
        };
        let [vyre::ir::Node::Region { generator, .. }] = body.as_ref().as_slice() else {
            panic!("expected CRC32 wrapper to contain one primitive child region");
        };
        assert_eq!(generator.as_str(), CRC32_OP_ID);
    }

    #[test]
    fn generic_default_names_are_family_scoped() {
        let program = crc32("input", "out", 4);
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
