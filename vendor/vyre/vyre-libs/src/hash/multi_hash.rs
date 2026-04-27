//! Cat-A `multi_hash` — CRC-32 + FNV-1a 32-bit + Adler-32 in one pass.
//!
//! Single lane-0 guarded walk over `input[0..]`.  Each iteration updates
//! all three hash states using the same loaded byte, so the buffer is
//! walked exactly once.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

#[cfg(test)]
use crate::buffer_names::fixed_name;
use crate::buffer_names::scoped_generic_name;

const OP_ID: &str = "vyre-libs::hash::multi_hash";
const FAMILY_PREFIX: &str = "hash_multi";

const CRC32_POLY_REFLECTED: u32 = 0xEDB8_8320;
const CRC32_INIT: u32 = 0xFFFF_FFFF;
const CRC32_FINAL_XOR: u32 = 0xFFFF_FFFF;

const FNV1A32_OFFSET: u32 = 0x811c_9dc5;
const FNV1A32_PRIME: u32 = 0x0100_0193;

const MOD_ADLER: u32 = 65_521;

fn scoped_input_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "input", name, &["input"])
}

fn scoped_crc32_buffer(name: &str) -> String {
    scoped_generic_name(
        FAMILY_PREFIX,
        "out_crc32",
        name,
        &["out", "output", "crc32", "out_crc32"],
    )
}

fn scoped_fnv1a32_buffer(name: &str) -> String {
    scoped_generic_name(
        FAMILY_PREFIX,
        "out_fnv1a32",
        name,
        &["out", "output", "fnv1a32", "out_fnv1a32"],
    )
}

fn scoped_adler32_buffer(name: &str) -> String {
    scoped_generic_name(
        FAMILY_PREFIX,
        "out_adler32",
        name,
        &["out", "output", "adler32", "out_adler32"],
    )
}

/// Build a Program that computes CRC-32, FNV-1a 32-bit, and Adler-32 over
/// `input[0..n]` in a single walk.
///
/// `input[i]` packs one byte per u32 slot.  The three results are written
/// to `out_crc32[0]`, `out_fnv1a32[0]`, and `out_adler32[0]`.
#[must_use]
pub fn multi_hash(
    input: &str,
    out_crc32: &str,
    out_fnv1a32: &str,
    out_adler32: &str,
    n: u32,
) -> Program {
    let input = scoped_input_buffer(input);
    let out_crc32 = scoped_crc32_buffer(out_crc32);
    let out_fnv1a32 = scoped_fnv1a32_buffer(out_fnv1a32);
    let out_adler32 = scoped_adler32_buffer(out_adler32);

    let body = vec![crate::region::wrap_anonymous(
        OP_ID,
        vec![Node::if_then(
            Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
            vec![
                Node::let_bind("crc", Expr::u32(CRC32_INIT)),
                Node::let_bind("fnv", Expr::u32(FNV1A32_OFFSET)),
                Node::let_bind("a", Expr::u32(1)),
                Node::let_bind("b", Expr::u32(0)),
                Node::loop_for(
                    "i",
                    Expr::u32(0),
                    Expr::buf_len(&input),
                    vec![
                        Node::let_bind("byte", Expr::load(&input, Expr::var("i"))),
                        // CRC-32 update
                        Node::assign("crc", Expr::bitxor(Expr::var("crc"), Expr::var("byte"))),
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
                                        Expr::u32(CRC32_POLY_REFLECTED),
                                    )),
                                    false_val: Box::new(Expr::shr(Expr::var("crc"), Expr::u32(1))),
                                },
                            )],
                        ),
                        // FNV-1a 32 update
                        Node::assign("fnv", Expr::bitxor(Expr::var("fnv"), Expr::var("byte"))),
                        Node::assign("fnv", Expr::mul(Expr::var("fnv"), Expr::u32(FNV1A32_PRIME))),
                        // Adler-32 update
                        Node::assign(
                            "a",
                            Expr::rem(
                                Expr::add(Expr::var("a"), Expr::var("byte")),
                                Expr::u32(MOD_ADLER),
                            ),
                        ),
                        Node::assign(
                            "b",
                            Expr::rem(
                                Expr::add(Expr::var("b"), Expr::var("a")),
                                Expr::u32(MOD_ADLER),
                            ),
                        ),
                    ],
                ),
                Node::store(
                    &out_crc32,
                    Expr::u32(0),
                    Expr::bitxor(Expr::var("crc"), Expr::u32(CRC32_FINAL_XOR)),
                ),
                Node::store(&out_fnv1a32, Expr::u32(0), Expr::var("fnv")),
                Node::store(
                    &out_adler32,
                    Expr::u32(0),
                    Expr::bitor(Expr::shl(Expr::var("b"), Expr::u32(16)), Expr::var("a")),
                ),
            ],
        )],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(&input, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::output(&out_crc32, 1, DataType::U32).with_count(1),
            BufferDecl::read_write(&out_fnv1a32, 2, DataType::U32).with_count(1),
            BufferDecl::read_write(&out_adler32, 3, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        body,
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || multi_hash("input", "out_crc32", "out_fnv1a32", "out_adler32", 3),
        test_inputs: Some(|| {
            let mut bytes = Vec::with_capacity(12);
            for &b in b"abc" { bytes.extend_from_slice(&u32::from(b).to_le_bytes()); }
            vec![vec![
                bytes,
                vec![0u8; 4],
                vec![0u8; 4],
                vec![0u8; 4],
            ]]
        }),
        expected_output: Some(|| vec![vec![
            0x3524_41c2u32.to_le_bytes().to_vec(),
            0x1a47_e90bu32.to_le_bytes().to_vec(),
            0x024D_0127u32.to_le_bytes().to_vec(),
        ]]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{adler32, crc32, fnv1a32, pack_bytes_as_u32};
    use vyre_reference::value::Value;

    fn run_multi(bytes: &[u8]) -> (u32, u32, u32) {
        let n = bytes.len().max(1) as u32;
        let program = multi_hash("input", "out_crc32", "out_fnv1a32", "out_adler32", n);
        let mut input_bytes = pack_bytes_as_u32(bytes);
        input_bytes.resize(n as usize * 4, 0);
        let inputs = vec![
            Value::Bytes(input_bytes.into()),
            Value::Bytes(vec![0u8; 4].into()),
            Value::Bytes(vec![0u8; 4].into()),
            Value::Bytes(vec![0u8; 4].into()),
        ];
        let outputs =
            vyre_reference::reference_eval(&program, &inputs).expect("multi_hash must run");
        let crc = u32::from_le_bytes([
            outputs[0].to_bytes()[0],
            outputs[0].to_bytes()[1],
            outputs[0].to_bytes()[2],
            outputs[0].to_bytes()[3],
        ]);
        let fnv = u32::from_le_bytes([
            outputs[1].to_bytes()[0],
            outputs[1].to_bytes()[1],
            outputs[1].to_bytes()[2],
            outputs[1].to_bytes()[3],
        ]);
        let adler = u32::from_le_bytes([
            outputs[2].to_bytes()[0],
            outputs[2].to_bytes()[1],
            outputs[2].to_bytes()[2],
            outputs[2].to_bytes()[3],
        ]);
        (crc, fnv, adler)
    }

    fn run_crc32(bytes: &[u8]) -> u32 {
        let n = bytes.len().max(1) as u32;
        let program = crc32("input", "out", n);
        let mut input_bytes = pack_bytes_as_u32(bytes);
        input_bytes.resize(n as usize * 4, 0);
        let inputs = vec![
            Value::Bytes(input_bytes.into()),
            Value::Bytes(vec![0u8; 4].into()),
        ];
        let outputs = vyre_reference::reference_eval(&program, &inputs).expect("crc32 must run");
        let raw = outputs[0].to_bytes();
        u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])
    }

    fn run_fnv1a32(bytes: &[u8]) -> u32 {
        let program = fnv1a32("input", "out");
        let mut input_bytes = pack_bytes_as_u32(bytes);
        input_bytes.resize(input_bytes.len().max(4), 0);
        let inputs = vec![
            Value::Bytes(input_bytes.into()),
            Value::Bytes(vec![0u8; 4].into()),
        ];
        let outputs = vyre_reference::reference_eval(&program, &inputs).expect("fnv1a32 must run");
        let raw = outputs[0].to_bytes();
        u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])
    }

    fn run_adler32(bytes: &[u8]) -> u32 {
        let n = bytes.len().max(1) as u32;
        let program = adler32("input", "out", n);
        let mut input_bytes = pack_bytes_as_u32(bytes);
        input_bytes.resize(n as usize * 4, 0);
        let inputs = vec![
            Value::Bytes(input_bytes.into()),
            Value::Bytes(vec![0u8; 4].into()),
        ];
        let outputs = vyre_reference::reference_eval(&program, &inputs).expect("adler32 must run");
        let raw = outputs[0].to_bytes();
        u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])
    }

    #[test]
    fn abc_matches_expected() {
        let (crc, fnv, adler) = run_multi(b"abc");
        assert_eq!(crc, 0x3524_41c2);
        assert_eq!(fnv, 0x1a47_e90b);
        assert_eq!(adler, 0x024D_0127);
    }

    #[test]
    fn parity_with_individual_hashes_empty() {
        let bytes: Vec<u8> = vec![];
        let (crc, fnv, adler) = run_multi(&bytes);
        assert_eq!(crc, run_crc32(&bytes));
        assert_eq!(fnv, run_fnv1a32(&bytes));
        assert_eq!(adler, run_adler32(&bytes));
    }

    #[test]
    fn parity_with_individual_hashes_random() {
        for len in [1, 7, 64, 255, 1024] {
            let bytes: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(7).wrapping_add(13))
                .collect();
            let (crc, fnv, adler) = run_multi(&bytes);
            assert_eq!(crc, run_crc32(&bytes), "crc32 mismatch at len {}", len);
            assert_eq!(fnv, run_fnv1a32(&bytes), "fnv1a32 mismatch at len {}", len);
            assert_eq!(
                adler,
                run_adler32(&bytes),
                "adler32 mismatch at len {}",
                len
            );
        }
    }

    #[test]
    fn generic_default_names_are_family_scoped() {
        let program = multi_hash("input", "out_crc32", "out_fnv1a32", "out_adler32", 4);
        assert_eq!(
            program.buffers()[0].name(),
            fixed_name(FAMILY_PREFIX, "input")
        );
        assert_eq!(
            program.buffers()[1].name(),
            fixed_name(FAMILY_PREFIX, "out_crc32")
        );
        assert_eq!(
            program.buffers()[2].name(),
            fixed_name(FAMILY_PREFIX, "out_fnv1a32")
        );
        assert_eq!(
            program.buffers()[3].name(),
            fixed_name(FAMILY_PREFIX, "out_adler32")
        );
    }
}
