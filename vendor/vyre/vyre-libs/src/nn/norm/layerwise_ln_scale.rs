//! Layerwise LN scale: `y = layer_norm(x) * scale`.
//!
//! Category A — element-wise mul by per-dim learnable scale.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::region::wrap_anonymous;

const OP_ID: &str = "vyre-libs::nn::layerwise_ln_scale";

/// Build a Program: `output[i] = input[i] * scale[i]` (F32).
#[must_use]
pub fn layerwise_ln_scale(input: &str, scale: &str, output: &str, n: u32) -> Program {
    let i = Expr::var("i");
    let scaled = Expr::mul(Expr::load(input, i.clone()), Expr::load(scale, i.clone()));

    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::u32(n)),
            vec![Node::Store {
                buffer: output.into(),
                index: i,
                value: scaled,
            }],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::storage(scale, 1, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::output(output, 2, DataType::F32).with_count(n),
        ],
        [64, 1, 1],
        vec![wrap_anonymous(OP_ID, body)],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || layerwise_ln_scale("input", "scale", "output", 4),
        test_inputs: Some(|| {
            let to_f32 = |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_f32(&[1.0, 2.0, 3.0, 4.0]),  // input (post-LN)
                to_f32(&[0.5, 2.0, 1.0, 0.1]),  // scale
                vec![0u8; 4 * 4],
            ]]
        }),
        expected_output: Some(|| {
            let to_f32 = |w: &[f32]| w.iter().flat_map(|v| v.to_bits().to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_f32(&[0.5, 4.0, 3.0, 0.4])]]
        }),
    }
}
