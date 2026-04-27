//! Cat-A `crc32` — CRC-32 (ISO 3309 / ITU-T V.42) checksum.
//!
//! Serial single-invocation walk. Standard CRC-32 polynomial
//! 0xEDB88320 (reflected), init 0xFFFFFFFF, final XOR 0xFFFFFFFF,
//! computed bit-by-bit without a lookup table to keep the body
//! compact (well under the Tier-2 size cap).
//!
//! `input[i]` packs one byte per u32 slot (low 8 bits). `out[0]`
//! receives the final CRC-32.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

#[cfg(test)]
use crate::buffer_names::fixed_name;
use crate::buffer_names::scoped_generic_name;

const OP_ID: &str = "vyre-libs::hash::crc32";
const FAMILY_PREFIX: &str = "hash_crc32";
const POLY_REFLECTED: u32 = 0xEDB8_8320;
const INIT: u32 = 0xFFFF_FFFF;
const FINAL_XOR: u32 = 0xFFFF_FFFF;

fn scoped_input_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "input", name, &["input"])
}

fn scoped_output_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "out", name, &["out", "output"])
}

/// Build a Program that writes CRC-32(input[0..]) to `out[0]`.
#[must_use]
pub fn crc32(input: &str, out: &str, n: u32) -> Program {
    let input = scoped_input_buffer(input);
    let out = scoped_output_buffer(out);
    let body = vec![crate::region::wrap_anonymous(
        OP_ID,
        vec![Node::if_then(
            Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
            vec![
                Node::let_bind("crc", Expr::u32(INIT)),
                Node::loop_for(
                    "i",
                    Expr::u32(0),
                    Expr::buf_len(&input),
                    vec![
                        Node::assign(
                            "crc",
                            Expr::bitxor(Expr::var("crc"), Expr::load(&input, Expr::var("i"))),
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
                                        Expr::u32(POLY_REFLECTED),
                                    )),
                                    false_val: Box::new(Expr::shr(Expr::var("crc"), Expr::u32(1))),
                                },
                            )],
                        ),
                    ],
                ),
                Node::store(
                    &out,
                    Expr::u32(0),
                    Expr::bitxor(Expr::var("crc"), Expr::u32(FINAL_XOR)),
                ),
            ],
        )],
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(&input, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::output(&out, 1, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        body,
    )
}

#[cfg(test)]
fn cpu_ref(input: &[u8]) -> u32 {
    let mut crc: u32 = INIT;
    for &b in input {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if (crc & 1) != 0 {
                (crc >> 1) ^ POLY_REFLECTED
            } else {
                crc >> 1
            };
        }
    }
    crc ^ FINAL_XOR
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || crc32("input", "out", 3),
        test_inputs: Some(|| {
            let mut bytes = Vec::with_capacity(12);
            for &b in b"abc" { bytes.extend_from_slice(&u32::from(b).to_le_bytes()); }
            vec![vec![bytes, vec![0u8; 4]]]
        }),
        // Canonical CRC-32 of "abc" (reflected poly 0xEDB88320) = 0x352441c2.
        expected_output: Some(|| vec![vec![0x352441c2u32.to_le_bytes().to_vec()]]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::pack_bytes_as_u32;
    use vyre_reference::value::Value;

    fn run(bytes: &[u8]) -> u32 {
        let n = bytes.len().max(1) as u32;
        let program = crc32("input", "out", n);
        let inputs = vec![
            Value::Bytes(pack_bytes_as_u32(bytes).into()),
            Value::Bytes(vec![0u8; 4].into()),
        ];
        let outputs = vyre_reference::reference_eval(&program, &inputs).expect("crc32 must run");
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
