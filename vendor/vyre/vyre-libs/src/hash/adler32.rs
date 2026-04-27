//! Cat-A `adler32` — Adler-32 (RFC 1950) checksum.
//!
//! Serial single-invocation walk. A init 1, B init 0, both mod 65521
//! per byte. Output `(B << 16) | A`.
//!
//! `input[i]` packs one byte per u32 slot.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

#[cfg(test)]
use crate::buffer_names::fixed_name;
use crate::buffer_names::scoped_generic_name;

const OP_ID: &str = "vyre-libs::hash::adler32";
const FAMILY_PREFIX: &str = "hash_adler32";
const MOD_ADLER: u32 = 65_521;

fn scoped_input_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "input", name, &["input"])
}

fn scoped_output_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "out", name, &["out", "output"])
}

/// Build a Program that writes Adler-32(input[0..]) to `out[0]`.
#[must_use]
pub fn adler32(input: &str, out: &str, n: u32) -> Program {
    let input = scoped_input_buffer(input);
    let out = scoped_output_buffer(out);
    let body = vec![crate::region::wrap_anonymous(
        OP_ID,
        vec![Node::if_then(
            Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
            vec![
                Node::let_bind("a", Expr::u32(1)),
                Node::let_bind("b", Expr::u32(0)),
                Node::loop_for(
                    "i",
                    Expr::u32(0),
                    Expr::buf_len(&input),
                    vec![
                        Node::assign(
                            "a",
                            Expr::rem(
                                Expr::add(Expr::var("a"), Expr::load(&input, Expr::var("i"))),
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
                    &out,
                    Expr::u32(0),
                    Expr::bitor(Expr::shl(Expr::var("b"), Expr::u32(16)), Expr::var("a")),
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
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in input {
        a = (a + u32::from(byte)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || adler32("input", "out", 3),
        test_inputs: Some(|| {
            let mut bytes = Vec::with_capacity(12);
            for &b in b"abc" { bytes.extend_from_slice(&u32::from(b).to_le_bytes()); }
            vec![vec![bytes, vec![0u8; 4]]]
        }),
        // Adler-32("abc") = 0x024D0127 (a = 295, b = 589).
        expected_output: Some(|| vec![vec![0x024D_0127u32.to_le_bytes().to_vec()]]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::pack_bytes_as_u32;
    use vyre_reference::value::Value;

    fn run(bytes: &[u8]) -> u32 {
        let n = bytes.len().max(1) as u32;
        let program = adler32("input", "out", n);
        let inputs = vec![
            Value::Bytes(pack_bytes_as_u32(bytes).into()),
            Value::Bytes(vec![0u8; 4].into()),
        ];
        let outputs = vyre_reference::reference_eval(&program, &inputs).expect("adler32 must run");
        let raw = outputs[0].to_bytes();
        u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])
    }

    #[test]
    fn abc_matches_rfc1950_example() {
        assert_eq!(run(b"abc"), 0x024D_0127);
        assert_eq!(run(b"abc"), cpu_ref(b"abc"));
    }

    #[test]
    fn wikipedia_string() {
        assert_eq!(run(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn random_64_bytes_match_ref() {
        let bytes: Vec<u8> = (0u8..64).collect();
        assert_eq!(run(&bytes), cpu_ref(&bytes));
    }

    #[test]
    fn generic_default_names_are_family_scoped() {
        let program = adler32("input", "out", 4);
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
