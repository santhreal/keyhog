//! SiLU (Sigmoid Linear Unit): `y = x * sigmoid(x) = x / (1 + exp(-x))`.
//!
//! Category A composition.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};

use crate::region::wrap_anonymous;

/// Build a Program that applies SiLU element-wise from `input` into
/// `output`. `n` is the element count of both buffers.
#[must_use]
pub fn silu(input: &str, output: &str, n: u32) -> Program {
    let i = Expr::var("i");
    let x = Expr::load(input, i.clone());

    // sigmoid(x) = 1.0 / (1.0 + exp(-x))
    let sigmoid_x = Expr::div(
        Expr::f32(1.0),
        Expr::add(
            Expr::f32(1.0),
            Expr::UnOp {
                op: UnOp::Exp,
                operand: Box::new(Expr::UnOp {
                    op: UnOp::Negate,
                    operand: Box::new(x.clone()),
                }),
            },
        ),
    );

    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::buf_len(input)),
            vec![Node::Store {
                buffer: output.into(),
                index: i,
                value: Expr::mul(x, sigmoid_x),
            }],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::output(output, 1, DataType::F32).with_count(n),
        ],
        [64, 1, 1],
        vec![wrap_anonymous("vyre-libs::nn::silu", body)],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::nn::silu",
        build: || silu("input", "output", 4),
        test_inputs: Some(|| {
            let to_bytes = |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0.0_f32, 1.0, -1.0, 2.0]), // input
                vec![0u8; 4 * 4],                      // output (zeroed)
            ]]
        }),
        expected_output: Some(|| {
            // SiLU via the same x / (1 + exp(-x)) formula the IR evaluates.
            // The cross-backend f32 ULP tolerance in parity_matrix
            // widens to 64 ULP for transcendentals, so this CPU-side
            // value is byte-identical with the reference interpreter.
            let input = [0.0_f32, 1.0, -1.0, 2.0];
            let out: Vec<f32> = input
                .iter()
                .map(|x| x / (1.0 + (-x).exp()))
                .collect();
            let bytes = out
                .iter()
                .flat_map(|v| v.to_bits().to_le_bytes())
                .collect::<Vec<u8>>();
            vec![vec![bytes]]
        }),
    }
}
