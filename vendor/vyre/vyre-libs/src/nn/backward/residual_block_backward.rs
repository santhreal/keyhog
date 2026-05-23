//! Backward for `parallel_residual_block`:
//!
//! Forward: `out = x + attn_out + mlp_out`
//! Backward: `grad_x = grad_attn = grad_mlp = grad_out` (addition broadcast).

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::region::wrap_anonymous;

const OP_ID: &str = "vyre-libs::nn::residual_block_backward";

/// Backward for parallel_residual_block (F32).
///
/// Since forward is just addition, all three input gradients equal grad_out.
/// This op copies grad_out → grad_x, grad_attn, grad_mlp.
#[must_use]
pub fn residual_block_backward(
    grad_out: &str,
    grad_x: &str,
    grad_attn: &str,
    grad_mlp: &str,
    n: u32,
) -> Program {
    let i = Expr::var("i");
    let dy = Expr::load(grad_out, i.clone());

    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::u32(n)),
            vec![
                Node::Store {
                    buffer: grad_x.into(),
                    index: i.clone(),
                    value: dy.clone(),
                },
                Node::Store {
                    buffer: grad_attn.into(),
                    index: i.clone(),
                    value: dy.clone(),
                },
                Node::Store {
                    buffer: grad_mlp.into(),
                    index: i,
                    value: dy,
                },
            ],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(grad_out, 0, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::output(grad_x, 1, DataType::F32).with_count(n),
            BufferDecl::output(grad_attn, 2, DataType::F32).with_count(n),
            BufferDecl::output(grad_mlp, 3, DataType::F32).with_count(n),
        ],
        [64, 1, 1],
        vec![wrap_anonymous(OP_ID, body)],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || residual_block_backward("grad_out", "grad_x", "grad_attn", "grad_mlp", 4),
        test_inputs: Some(|| {
            let to_f32 = |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_f32(&[1.0, 2.0, 3.0, 4.0]),
                vec![0u8; 4 * 4], // grad_x
                vec![0u8; 4 * 4], // grad_attn
                vec![0u8; 4 * 4], // grad_mlp
            ]]
        }),
        expected_output: Some(|| {
            // All three outputs = copy of grad_out. Test grad_x (buffer 1).
            let to_f32 = |w: &[f32]| w.iter().flat_map(|v| v.to_bits().to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_f32(&[1.0, 2.0, 3.0, 4.0])]]
        }),
        category: Some("nn"),
    }
}
