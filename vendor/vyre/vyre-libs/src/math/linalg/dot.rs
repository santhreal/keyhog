//! Dot product — element-wise multiply + sum-reduce.
//!
//! Category A composition: reads two equally-sized u32 buffers,
//! multiplies element-wise, reduces to one scalar via a single-lane
//! sequential loop. A parallel workgroup-cooperative variant ships
//! when FINDING-PRIM-1's workgroup scan primitive lands.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre_primitives::math::dot_partial::dot_partial;

use crate::region::wrap_anonymous;

/// Build a Program that computes the dot product of `lhs` and `rhs`
/// (both length `n`) into `out[0]`.
///
/// Buffers:
/// - `lhs` (u32, read-only, n elems)
/// - `rhs` (u32, read-only, n elems)
/// - `out` (u32, output, 1 elem)
///
/// Workgroup size `[1, 1, 1]`: lane 0 walks the vectors once and
/// writes the reduced scalar. Correct on every backend because it
/// uses no atomics; the parallel variant (FINDING-PRIM-1) layers on
/// top later without changing this op's CPU ref output.
///
/// # Errors
/// Returns `Err` when `n == 0` — empty reductions are rejected
/// (FINDING-V7-TEST-009-DOT).
pub fn dot(lhs: &str, rhs: &str, out: &str, n: u32) -> Result<Program, String> {
    if n == 0 {
        return Err("Fix: dot n=0 is invalid: empty reduction".to_string());
    }
    let body = dot_body(lhs, rhs, out, n);
    let region = wrap_anonymous("vyre-libs::math::dot", body);
    Ok(Program::wrapped(
        vec![
            BufferDecl::storage(lhs, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::storage(rhs, 1, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::output(out, 2, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![region],
    ))
}

fn dot_body(lhs: &str, rhs: &str, out: &str, n: u32) -> Vec<Node> {
    vec![
        Node::let_bind("acc", Expr::u32(0)),
        // Tier-2.5 primitive: walks `dk in 0..n` and accumulates
        // `lhs[dk] * rhs[dk]` into `acc`. Shared with nn::attention
        // score-pass and any future caller that needs the inner
        // multiply-accumulate shape.
        dot_partial(lhs, rhs, "acc", Expr::u32(0), Expr::u32(0), n),
        Node::Store {
            buffer: out.into(),
            index: Expr::u32(0),
            value: Expr::var("acc"),
        },
    ]
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::math::dot",
        build: || dot("lhs", "rhs", "out", 3).unwrap(),
        test_inputs: Some(|| vec![vec![
            [1u32, 2, 3].iter().flat_map(|v| v.to_le_bytes()).collect(),
            [4u32, 5, 6].iter().flat_map(|v| v.to_le_bytes()).collect(),
            vec![0u8; 4],
        ]]),
        expected_output: Some(|| vec![vec![
            // Only output buffer: out[0] = 1*4 + 2*5 + 3*6 = 32
            32u32.to_le_bytes().to_vec(),
        ]]),
    }
}
