//! DEFLATE stored-block inflate primitive body.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::{GeneratorRef, Ident};
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id for stored-block inflate.
pub const INFLATE_STORED_OP_ID: &str = "vyre-primitives::decode::inflate_stored";
/// Fixed-Huffman block diagnostic.
pub const FIXED_HUFFMAN_FIX: &str = "Fix: implement DEFLATE fixed-Huffman decode in vyre-primitives::decode::inflate before dispatching BTYPE=1 blocks.";
/// Dynamic-Huffman block diagnostic.
pub const DYNAMIC_HUFFMAN_FIX: &str = "Fix: implement DEFLATE dynamic-Huffman table construction + decode in vyre-primitives::decode::inflate before dispatching BTYPE=2 blocks.";
/// Reserved BTYPE diagnostic.
pub const RESERVED_BTYPE_FIX: &str =
    "Fix: reject reserved DEFLATE BTYPE=3 inputs before dispatching vyre-primitives::decode::inflate.";
/// Stored block LEN/NLEN diagnostic.
pub const STORED_HEADER_FIX: &str =
    "Fix: validate LEN/NLEN before copying a stored DEFLATE block in vyre-primitives::decode::inflate.";

/// Build the reusable stored-block inflate body.
#[must_use]
pub fn inflate_stored_body(input: &str, output: &str, inflated_len_buffer: &str) -> Vec<Node> {
    vec![
        Node::let_bind("lane", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::eq(Expr::var("lane"), Expr::u32(0)),
            vec![Node::store(inflated_len_buffer, Expr::u32(0), Expr::u32(0))],
        ),
        Node::let_bind("header", Expr::load(input, Expr::u32(0))),
        Node::let_bind(
            "btype",
            Expr::bitand(Expr::shr(Expr::var("header"), Expr::u32(1)), Expr::u32(0x3)),
        ),
        Node::if_then(
            Expr::eq(Expr::var("btype"), Expr::u32(0)),
            vec![
                Node::let_bind(
                    "len",
                    Expr::bitor(
                        Expr::load(input, Expr::u32(1)),
                        Expr::shl(Expr::load(input, Expr::u32(2)), Expr::u32(8)),
                    ),
                ),
                Node::let_bind(
                    "nlen",
                    Expr::bitor(
                        Expr::load(input, Expr::u32(3)),
                        Expr::shl(Expr::load(input, Expr::u32(4)), Expr::u32(8)),
                    ),
                ),
                Node::if_then(
                    Expr::eq(
                        Expr::var("nlen"),
                        Expr::bitxor(Expr::var("len"), Expr::u32(0xFFFF)),
                    ),
                    vec![
                        Node::if_then(
                            Expr::eq(Expr::var("lane"), Expr::u32(0)),
                            vec![Node::store(
                                inflated_len_buffer,
                                Expr::u32(0),
                                Expr::var("len"),
                            )],
                        ),
                        Node::if_then(
                            Expr::lt(Expr::var("lane"), Expr::var("len")),
                            vec![Node::store(
                                output,
                                Expr::var("lane"),
                                Expr::load(input, Expr::add(Expr::u32(5), Expr::var("lane"))),
                            )],
                        ),
                    ],
                ),
                Node::if_then(
                    Expr::ne(
                        Expr::var("nlen"),
                        Expr::bitxor(Expr::var("len"), Expr::u32(0xFFFF)),
                    ),
                    vec![Node::trap(Expr::u32(0), STORED_HEADER_FIX)],
                ),
            ],
        ),
        Node::if_then(
            Expr::eq(Expr::var("btype"), Expr::u32(1)),
            vec![Node::trap(Expr::u32(1), FIXED_HUFFMAN_FIX)],
        ),
        Node::if_then(
            Expr::eq(Expr::var("btype"), Expr::u32(2)),
            vec![Node::trap(Expr::u32(2), DYNAMIC_HUFFMAN_FIX)],
        ),
        Node::if_then(
            Expr::eq(Expr::var("btype"), Expr::u32(3)),
            vec![Node::trap(Expr::u32(3), RESERVED_BTYPE_FIX)],
        ),
    ]
}

/// Wrap the stored-block inflate body as a child of `parent_op_id`.
#[must_use]
pub fn inflate_stored_child(
    parent_op_id: &str,
    input: &str,
    output: &str,
    inflated_len_buffer: &str,
) -> Node {
    Node::Region {
        generator: Ident::from(INFLATE_STORED_OP_ID),
        source_region: Some(GeneratorRef {
            name: parent_op_id.to_string(),
        }),
        body: Arc::new(inflate_stored_body(input, output, inflated_len_buffer)),
    }
}

/// Standalone stored-block inflate program for primitive-level conformance.
#[must_use]
pub fn inflate_stored(
    input: &str,
    output: &str,
    inflated_len_buffer: &str,
    input_len: u32,
) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(input_len),
            BufferDecl::output(output, 1, DataType::U32).with_count(input_len),
            BufferDecl::read_write(inflated_len_buffer, 2, DataType::U32).with_count(1),
        ],
        [64, 1, 1],
        vec![Node::Region {
            generator: Ident::from(INFLATE_STORED_OP_ID),
            source_region: None,
            body: Arc::new(inflate_stored_body(input, output, inflated_len_buffer)),
        }],
    )
}

#[cfg(feature = "inventory-registry")]
fn pack_words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        INFLATE_STORED_OP_ID,
        || inflate_stored("input", "output", "inflated_len", 10),
        Some(|| vec![vec![
            pack_words(&[
                0x01,
                0x05,
                0x00,
                0xFA,
                0xFF,
                u32::from(b'h'),
                u32::from(b'e'),
                u32::from(b'l'),
                u32::from(b'l'),
                u32::from(b'o'),
            ]),
            vec![0; 40],
            vec![0; 4],
        ]]),
        Some(|| vec![vec![
            pack_words(&[
                u32::from(b'h'),
                u32::from(b'e'),
                u32::from(b'l'),
                u32::from(b'l'),
                u32::from(b'o'),
                0,
                0,
                0,
                0,
                0,
            ]),
            pack_words(&[5]),
        ]]),
    )
}
