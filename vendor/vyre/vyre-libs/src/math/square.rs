//! Element-wise square: `y = x * x`.
//!
//! Category-A composition.

use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Build a Program that computes `output[i] = input[i] * input[i]`.
#[must_use]
pub fn square(input: &str, output: &str, n: u32) -> Program {
    let i = Expr::var("i");
    let val = Expr::load(input, i.clone());

    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::u32(n)),
            vec![Node::Store {
                buffer: output.into(),
                index: i,
                value: Expr::mul(val.clone(), val),
            }],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::output(output, 1, DataType::F32).with_count(n),
        ],
        [64, 1, 1],
        vec![wrap_anonymous("vyre-libs::math::square", body)],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::math::square",
        build: || square("input", "output", 4),
        test_inputs: Some(|| {
            let to_bytes = |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[2.0_f32, 3.0, 4.0, 5.0]), // input
                vec![0u8; 4 * 4],                     // output (zeroed)
            ]]
        }),
        expected_output: Some(|| {
            let to_bytes = |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[4.0_f32, 9.0, 16.0, 25.0]), // output = x*x
            ]]
        }),
    }
}
