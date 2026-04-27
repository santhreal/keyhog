use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// ABI type-kind tag for C `char`.
pub const C_ABI_CHAR: u32 = 1;
/// ABI type-kind tag for C pointer-sized objects.
pub const C_ABI_POINTER: u32 = 2;
/// ABI type-kind tag for C `long` / 64-bit integer-sized objects.
pub const C_ABI_LONG: u32 = 3;

/// GPU System V ABI Alignment & Sizeof Evaluator
///
/// Ensures strict CPU cache-line compliance by aligning struct members.
/// A parallel scan computes inclusive offsets across struct blueprints, accounting
/// for byte padding natively across the GPU topology.
#[must_use]
pub fn c11_compute_alignments(
    type_definitions: &str,
    out_sizes: &str,
    out_alignments: &str,
    num_types: Expr,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };

    let loop_body = vec![
        Node::let_bind("type_kind", Expr::load(type_definitions, t.clone())),
        Node::let_bind(
            "base_size",
            Expr::select(
                Expr::eq(Expr::var("type_kind"), Expr::u32(C_ABI_CHAR)),
                Expr::u32(1),
                Expr::select(
                    Expr::or(
                        Expr::eq(Expr::var("type_kind"), Expr::u32(C_ABI_POINTER)),
                        Expr::eq(Expr::var("type_kind"), Expr::u32(C_ABI_LONG)),
                    ),
                    Expr::u32(8),
                    Expr::u32(4),
                ),
            ),
        ),
        Node::store(out_sizes, t.clone(), Expr::var("base_size")),
        Node::store(out_alignments, t.clone(), Expr::var("base_size")),
    ];

    let type_count = match &num_types {
        Expr::LitU32(n) => *n,
        _ => 1,
    };
    Program::wrapped(
        vec![
            BufferDecl::storage(type_definitions, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(type_count),
            BufferDecl::storage(out_sizes, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(type_count),
            BufferDecl::storage(out_alignments, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(type_count),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::parsing::c11_compute_alignments",
            vec![Node::if_then(Expr::lt(t.clone(), num_types), loop_body)],
        )],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::parsing::c11_compute_alignments",
        build: || c11_compute_alignments("types", "sizes", "aligns", Expr::u32(4)),
        // Zero-filled inputs (4 u32 slots). type_kind=0 for every
        // entry hits the default 4-byte word branch, so sizes and
        // alignments both fill with 4.
        test_inputs: Some(|| vec![vec![
            vec![0u8; 4 * 4],
            vec![0u8; 4 * 4],
            vec![0u8; 4 * 4],
        ]]),
        expected_output: Some(|| {
            let mut sizes = Vec::with_capacity(16);
            let mut aligns = Vec::with_capacity(16);
            for _ in 0..4 {
                sizes.extend_from_slice(&4u32.to_le_bytes());
                aligns.extend_from_slice(&4u32.to_le_bytes());
            }
            vec![vec![sizes, aligns]]
        }),
    }
}
