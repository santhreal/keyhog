//! Arithmetic mean reduction: `y = sum(x) / n`.
//!
//! Category-A composition.

use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Build a Program that computes the mean of `input` into `output[0]`.
#[must_use]
pub fn reduce_mean(input: &str, output: &str, n: u32) -> Program {
    let body = vec![
        Node::let_bind("sum", Expr::f32(0.0)),
        Node::loop_for(
            "i",
            Expr::u32(0),
            Expr::u32(n),
            vec![Node::assign(
                "sum",
                Expr::add(Expr::var("sum"), Expr::load(input, Expr::var("i"))),
            )],
        ),
        Node::Store {
            buffer: output.into(),
            index: Expr::u32(0),
            value: Expr::div(Expr::var("sum"), Expr::f32(n as f32)),
        },
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::output(output, 1, DataType::F32).with_count(1),
        ],
        [1, 1, 1],
        vec![wrap_anonymous("vyre-libs::math::reduce_mean", body)],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::math::reduce_mean",
        build: || reduce_mean("input", "output", 4),
        test_inputs: Some(|| {
            let to_bytes = |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[1.0_f32, 2.0, 3.0, 4.0]), // input
                vec![0u8; 4],                         // output (single f32)
            ]]
        }),
        expected_output: Some(|| {
            let to_bytes = |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[2.5_f32]), // mean of [1,2,3,4]
            ]]
        }),
    }
}
