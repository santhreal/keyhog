//! Backward for `logit_softcap`: `d/dx [tanh(x/cap) * cap] = 1 - tanh²(x/cap)`.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};

use crate::region::wrap_anonymous;

const OP_ID: &str = "vyre-libs::nn::logit_softcap_backward";

/// Backward for logit_softcap (F32).
#[must_use]
pub fn logit_softcap_backward(
    input: &str,
    grad_out: &str,
    grad_in: &str,
    n: u32,
    cap: f32,
) -> Program {
    let i = Expr::var("i");
    let x = Expr::load(input, i.clone());
    let dy = Expr::load(grad_out, i.clone());

    let t = Expr::UnOp {
        op: UnOp::Tanh,
        operand: Box::new(Expr::div(x, Expr::f32(cap))),
    };
    let local_grad = Expr::sub(Expr::f32(1.0), Expr::mul(t.clone(), t));
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
        build: || logit_softcap_backward("input", "grad_out", "grad_in", 4, 30.0),
        test_inputs: Some(|| {
            let to_f32 = |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_f32(&[0.0, 15.0, -60.0, 100.0]),
                to_f32(&[1.0, 1.0, 1.0, 1.0]),
                vec![0u8; 4 * 4],
            ]]
        }),
        expected_output: Some(|| {
            let out = [
                f32::from_bits(0x3f80_0000),
                f32::from_bits(0x3f49_54a4),
                f32::from_bits(0x3d90_b160),
                f32::from_bits(0x3ba6_6200),
            ];
            let bytes = out.iter().flat_map(|v| v.to_bits().to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![bytes]]
        }),
        category: Some("nn"),
    }
}
