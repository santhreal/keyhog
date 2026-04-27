//! Base64 decode primitive body.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::{GeneratorRef, Ident};
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id for base64 decode.
pub const BASE64_DECODE_OP_ID: &str = "vyre-primitives::decode::base64_decode";
/// Base64 padding byte.
pub const PAD: u32 = b'=' as u32;
/// Invalid table entry sentinel.
pub const INVALID: u32 = 0xFF;

fn blocks_for_len(input_len: u32) -> u32 {
    input_len / 4
}

/// Decoded capacity for a padded base64 input.
#[must_use]
pub fn decoded_capacity(input_len: u32) -> u32 {
    blocks_for_len(input_len).saturating_mul(3)
}

fn clamp_lookup(name: &str, table: &str) -> Vec<Node> {
    vec![
        Node::let_bind(format!("{name}_raw"), Expr::load(table, Expr::var(name))),
        Node::let_bind(
            format!("{name}_v"),
            Expr::select(
                Expr::eq(Expr::var(format!("{name}_raw")), Expr::u32(INVALID)),
                Expr::u32(0),
                Expr::var(format!("{name}_raw")),
            ),
        ),
    ]
}

/// Build the reusable base64 decode body.
#[must_use]
pub fn base64_decode_body(
    input: &str,
    table: &str,
    output: &str,
    decoded_len_buffer: &str,
    input_len: u32,
) -> Vec<Node> {
    let decoded_len = decoded_capacity(input_len);
    let mut body = vec![Node::let_bind("j", Expr::InvocationId { axis: 0 })];
    if input_len >= 2 {
        body.push(Node::if_then(
            Expr::eq(Expr::var("j"), Expr::u32(0)),
            vec![
                Node::let_bind(
                    "tail_pad_1",
                    Expr::select(
                        Expr::eq(Expr::load(input, Expr::u32(input_len - 1)), Expr::u32(PAD)),
                        Expr::u32(1),
                        Expr::u32(0),
                    ),
                ),
                Node::let_bind(
                    "tail_pad_2",
                    Expr::select(
                        Expr::eq(Expr::load(input, Expr::u32(input_len - 2)), Expr::u32(PAD)),
                        Expr::u32(1),
                        Expr::u32(0),
                    ),
                ),
                Node::store(
                    decoded_len_buffer,
                    Expr::u32(0),
                    Expr::sub(
                        Expr::sub(Expr::u32(decoded_len), Expr::var("tail_pad_1")),
                        Expr::var("tail_pad_2"),
                    ),
                ),
            ],
        ));
    } else {
        body.push(Node::if_then(
            Expr::eq(Expr::var("j"), Expr::u32(0)),
            vec![Node::store(decoded_len_buffer, Expr::u32(0), Expr::u32(0))],
        ));
    }
    body.push(Node::if_then(
        Expr::lt(Expr::var("j"), Expr::u32(decoded_len)),
        {
            let mut per_byte = vec![
                Node::let_bind("quad", Expr::div(Expr::var("j"), Expr::u32(3))),
                Node::let_bind("in_base", Expr::mul(Expr::var("quad"), Expr::u32(4))),
                Node::let_bind(
                    "pos",
                    Expr::sub(Expr::var("j"), Expr::mul(Expr::var("quad"), Expr::u32(3))),
                ),
                Node::let_bind("c0", Expr::load(input, Expr::var("in_base"))),
                Node::let_bind(
                    "c1",
                    Expr::load(input, Expr::add(Expr::var("in_base"), Expr::u32(1))),
                ),
                Node::let_bind(
                    "c2",
                    Expr::load(input, Expr::add(Expr::var("in_base"), Expr::u32(2))),
                ),
                Node::let_bind(
                    "c3",
                    Expr::load(input, Expr::add(Expr::var("in_base"), Expr::u32(3))),
                ),
                Node::let_bind("pad2", Expr::eq(Expr::var("c2"), Expr::u32(PAD))),
                Node::let_bind("pad1", Expr::eq(Expr::var("c3"), Expr::u32(PAD))),
            ];
            per_byte.extend(clamp_lookup("c0", table));
            per_byte.extend(clamp_lookup("c1", table));
            per_byte.extend(clamp_lookup("c2", table));
            per_byte.extend(clamp_lookup("c3", table));
            per_byte.extend([
                Node::let_bind(
                    "b0",
                    Expr::bitor(
                        Expr::shl(Expr::var("c0_v"), Expr::u32(2)),
                        Expr::shr(Expr::var("c1_v"), Expr::u32(4)),
                    ),
                ),
                Node::let_bind(
                    "b1",
                    Expr::bitor(
                        Expr::shl(
                            Expr::bitand(Expr::var("c1_v"), Expr::u32(0x0F)),
                            Expr::u32(4),
                        ),
                        Expr::shr(Expr::var("c2_v"), Expr::u32(2)),
                    ),
                ),
                Node::let_bind(
                    "b2",
                    Expr::bitor(
                        Expr::shl(
                            Expr::bitand(Expr::var("c2_v"), Expr::u32(0x03)),
                            Expr::u32(6),
                        ),
                        Expr::var("c3_v"),
                    ),
                ),
                Node::if_then(
                    Expr::eq(Expr::var("pos"), Expr::u32(0)),
                    vec![Node::store(output, Expr::var("j"), Expr::var("b0"))],
                ),
                Node::if_then(
                    Expr::eq(Expr::var("pos"), Expr::u32(1)),
                    vec![Node::if_then(
                        Expr::eq(Expr::var("pad2"), Expr::bool(false)),
                        vec![Node::store(output, Expr::var("j"), Expr::var("b1"))],
                    )],
                ),
                Node::if_then(
                    Expr::eq(Expr::var("pos"), Expr::u32(2)),
                    vec![Node::if_then(
                        Expr::eq(Expr::var("pad1"), Expr::bool(false)),
                        vec![Node::store(output, Expr::var("j"), Expr::var("b2"))],
                    )],
                ),
            ]);
            per_byte
        },
    ));
    body
}

/// Wrap the base64 decode body as a child of `parent_op_id`.
#[must_use]
pub fn base64_decode_child(
    parent_op_id: &str,
    input: &str,
    table: &str,
    output: &str,
    decoded_len_buffer: &str,
    input_len: u32,
) -> Node {
    Node::Region {
        generator: Ident::from(BASE64_DECODE_OP_ID),
        source_region: Some(GeneratorRef {
            name: parent_op_id.to_string(),
        }),
        body: Arc::new(base64_decode_body(
            input,
            table,
            output,
            decoded_len_buffer,
            input_len,
        )),
    }
}

/// Standalone base64 decode program for primitive-level conformance.
#[must_use]
pub fn base64_decode(
    input: &str,
    table: &str,
    output: &str,
    decoded_len_buffer: &str,
    input_len: u32,
) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(input_len),
            BufferDecl::storage(table, 1, BufferAccess::ReadOnly, DataType::U32).with_count(256),
            BufferDecl::output(output, 2, DataType::U32).with_count(decoded_capacity(input_len)),
            BufferDecl::read_write(decoded_len_buffer, 3, DataType::U32).with_count(1),
        ],
        [64, 1, 1],
        vec![Node::Region {
            generator: Ident::from(BASE64_DECODE_OP_ID),
            source_region: None,
            body: Arc::new(base64_decode_body(
                input,
                table,
                output,
                decoded_len_buffer,
                input_len,
            )),
        }],
    )
}

#[cfg(feature = "inventory-registry")]
fn pack_words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

#[cfg(feature = "inventory-registry")]
fn base64_table() -> [u32; 256] {
    let mut table = [INVALID; 256];
    let mut byte = b'A';
    while byte <= b'Z' {
        table[byte as usize] = u32::from(byte - b'A');
        byte += 1;
    }
    byte = b'a';
    while byte <= b'z' {
        table[byte as usize] = u32::from(byte - b'a' + 26);
        byte += 1;
    }
    byte = b'0';
    while byte <= b'9' {
        table[byte as usize] = u32::from(byte - b'0' + 52);
        byte += 1;
    }
    table[b'+' as usize] = 62;
    table[b'/' as usize] = 63;
    table[b'=' as usize] = 0;
    table
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        BASE64_DECODE_OP_ID,
        || base64_decode("input", "table", "output", "decoded_len", 4),
        Some(|| vec![vec![
            pack_words(&[u32::from(b'T'), u32::from(b'W'), u32::from(b'F'), u32::from(b'u')]),
            pack_words(base64_table().as_ref()),
            vec![0; 12],
            vec![0; 4],
        ]]),
        Some(|| vec![vec![
            pack_words(&[u32::from(b'M'), u32::from(b'a'), u32::from(b'n')]),
            pack_words(&[3]),
        ]]),
    )
}
