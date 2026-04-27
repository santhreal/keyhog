//! Scalar broadcast — copy a single-element `src` to every slot of `dst`.
//!
//! Category A composition. The minimal broadcast case; a full
//! shape-broadcasting version (NumPy semantics) belongs in a future
//! `broadcast_shaped` function that takes source + target shapes.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::region::wrap_anonymous;

/// Broadcast a scalar into every element of `dst`. `n` is the target
/// element count — `dst` receives `n × sizeof(U32)` bytes.
#[must_use]
pub fn broadcast(src: &str, dst: &str, n: u32) -> Program {
    let output = BufferDecl::output(dst, 1, DataType::U32)
        .with_count(n.max(1))
        .with_output_byte_range(0..(n as usize).saturating_mul(4));
    let body = vec![
        Node::let_bind("idx", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(Expr::var("idx"), Expr::u32(n)),
            vec![Node::Store {
                buffer: dst.into(),
                index: Expr::var("idx"),
                value: Expr::load(src, Expr::u32(0)),
            }],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(src, 0, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            output,
        ],
        [64, 1, 1],
        vec![wrap_anonymous("vyre-libs::math::broadcast", body)],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::math::broadcast",
        build: || broadcast("src", "dst", 4),
        test_inputs: Some(|| vec![vec![
            42u32.to_le_bytes().to_vec(),                       // src: scalar 42
            vec![0u8; 4 * 4],                                   // dst: 4 zeroed slots
        ]]),
        expected_output: Some(|| vec![vec![
            // Only ReadWrite buffer: dst filled with 42
            [42u32, 42, 42, 42].iter().flat_map(|v| v.to_le_bytes()).collect(),
        ]]),
    }
}
