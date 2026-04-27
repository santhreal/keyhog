//! Prefix-sum scan — inclusive scan over a u32 buffer.
//!
//! Category A composition. Single-workgroup sequential version;
//! callers with large arrays should lower into a Blelloch tree-scan
//! variant (future `scan_prefix_sum_parallel`).

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::region::wrap_anonymous;

/// Build a Program that computes the inclusive prefix sum of `input`
/// into `output`, both sized `n`.
///
/// The first invocation does the entire scan sequentially. This is
/// correct and slow — O(n) work, one-threaded. The parallel Blelloch
/// version belongs in a future `scan_prefix_sum_parallel`.
///
/// **Overflow semantics** (V7-CORR-018): all accumulator additions
/// use `u32::wrapping_add`. For inputs whose cumulative sum exceeds
/// `u32::MAX`, the output wraps modulo 2^32. Callers that need
/// saturation or a larger accumulator must cast to f32 first (via a
/// companion `scan_prefix_sum_f32` — future op) or split the input
/// into chunks small enough to avoid overflow.
#[must_use]
pub fn scan_prefix_sum(input: &str, output: &str, n: u32) -> Program {
    let input_decl = BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32);
    let input_decl = if n == 0 {
        input_decl
    } else {
        input_decl.with_count(n)
    };
    let output_decl = BufferDecl::output(output, 1, DataType::U32)
        .with_count(n.max(1))
        .with_output_byte_range(0..(n as usize).saturating_mul(4));
    let body = scan_body(input, output, n);
    let region = wrap_anonymous("vyre-libs::math::scan_prefix_sum", body);
    Program::wrapped(vec![input_decl, output_decl], [1, 1, 1], vec![region])
}

fn scan_body(input: &str, output: &str, n: u32) -> Vec<Node> {
    vec![Node::if_then(
        Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
        vec![
            Node::let_bind("acc", Expr::u32(0)),
            Node::loop_for(
                "i",
                Expr::u32(0),
                Expr::u32(n),
                vec![
                    Node::assign(
                        "acc",
                        Expr::add(Expr::var("acc"), Expr::load(input, Expr::var("i"))),
                    ),
                    Node::Store {
                        buffer: output.into(),
                        index: Expr::var("i"),
                        value: Expr::var("acc"),
                    },
                ],
            ),
        ],
    )]
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::math::scan_prefix_sum",
        build: || scan_prefix_sum("input", "output", 4),
        test_inputs: Some(|| vec![vec![
            [1u32, 2, 3, 4].iter().flat_map(|v| v.to_le_bytes()).collect(),
            vec![0u8; 4 * 4],
        ]]),
        expected_output: Some(|| vec![vec![
            // Only ReadWrite buffer: prefix sum [1, 3, 6, 10]
            [1u32, 3, 6, 10].iter().flat_map(|v| v.to_le_bytes()).collect(),
        ]]),
    }
}
