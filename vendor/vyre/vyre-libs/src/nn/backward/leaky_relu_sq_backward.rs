//! Backward for `leaky_relu_sq`: derivative of `max(αx, x)²`.
//!
//! For x≥0: d/dx = 2x. For x<0: d/dx = 2·(0.5x)·0.5 = 0.5x.
//! Branchless: `grad = dy * max(0.5*x, 2*x)`.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::region::wrap_anonymous;

const OP_ID: &str = "vyre-libs::nn::leaky_relu_sq_backward";

/// Backward for leaky_relu_sq (F32).
#[must_use]
pub fn leaky_relu_sq_backward(input: &str, grad_out: &str, grad_in: &str, n: u32) -> Program {
    let i = Expr::var("i");
    let x = Expr::load(input, i.clone());
    let dy = Expr::load(grad_out, i.clone());

    // Branchless: for x>=0 → 2x > 0.5x, for x<0 → 0.5x > 2x
    let local_grad = Expr::max(
        Expr::mul(Expr::f32(0.5), x.clone()),
        Expr::mul(Expr::f32(2.0), x),
    );
    let grad = Expr::mul(dy, local_grad);

    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::u32(n)),
            vec![Node::Store {
                buffer: grad_in.into(),
                index: i,
                value: grad,
            }],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::storage(grad_out, 1, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::output(grad_in, 2, DataType::F32).with_count(n),
        ],
        [64, 1, 1],
        vec![wrap_anonymous(OP_ID, body)],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || leaky_relu_sq_backward("input", "grad_out", "grad_in", 4),
        test_inputs: Some(|| {
            let to_f32 = |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_f32(&[2.0, -4.0, 0.0, 1.0]),
                to_f32(&[1.0, 1.0, 1.0, 1.0]),
                vec![0u8; 4 * 4],
            ]]
        }),
        expected_output: Some(|| {
            // x=2: max(1,4)=4; x=-4: max(-2,-8)=-2; x=0: 0; x=1: max(0.5,2)=2
            let out = [4.0_f32, -2.0, 0.0, 2.0];
            let bytes = out.iter().flat_map(|v| v.to_bits().to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![bytes]]
        }),
    }
}
