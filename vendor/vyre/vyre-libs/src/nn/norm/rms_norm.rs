//! RMS normalization: `y_i = x_i / sqrt(mean(x^2) + eps)`.
//!
//! Category-A composition.

use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};

/// Build a Program that applies RMSNorm element-wise.
/// For simplicity in this Tier 3 primitive, we assume input is one dimension `n`.
#[must_use]
pub fn rms_norm(input: &str, output: &str, n: u32, eps: f32) -> Program {
    // Pass 1: compute mean(x^2)
    // In a real optimized kernel, this would be a tiled reduction.
    // Here we use a naive loop for the Cat-A reference.
    let body = vec![
        Node::let_bind("sum_sq", Expr::f32(0.0)),
        Node::loop_for(
            "k",
            Expr::u32(0),
            Expr::u32(n),
            vec![
                Node::let_bind("val", Expr::load(input, Expr::var("k"))),
                Node::assign(
                    "sum_sq",
                    Expr::add(
                        Expr::var("sum_sq"),
                        Expr::mul(Expr::var("val"), Expr::var("val")),
                    ),
                ),
            ],
        ),
        Node::let_bind(
            "rms",
            Expr::UnOp {
                op: UnOp::InverseSqrt,
                operand: Box::new(Expr::add(
                    Expr::div(Expr::var("sum_sq"), Expr::f32(n as f32)),
                    Expr::f32(eps),
                )),
            },
        ),
        Node::let_bind("idx", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(Expr::var("idx"), Expr::u32(n)),
            vec![Node::Store {
                buffer: output.into(),
                index: Expr::var("idx"),
                value: Expr::mul(Expr::load(input, Expr::var("idx")), Expr::var("rms")),
            }],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::output(output, 1, DataType::F32).with_count(n),
        ],
        [64, 1, 1],
        vec![wrap_anonymous("vyre-libs::nn::rms_norm", body)],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::nn::rms_norm",
        build: || rms_norm("input", "output", 4, 1e-5),
        test_inputs: Some(|| {
            let to_bytes =
                |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // Input = [1.0, 2.0, 3.0, 4.0].
            vec![vec![to_bytes(&[1.0, 2.0, 3.0, 4.0]), vec![0u8; 4 * 4]]]
        }),
        expected_output: Some(|| {
            let to_bytes =
                |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // mean(x^2) = (1+4+9+16)/4 = 7.5.
            // rms = inverseSqrt(7.5 + 1e-5).
            // y_i = x_i * rms.
            let mean_sq = (1.0_f32 + 4.0 + 9.0 + 16.0) / 4.0;
            let rms = (mean_sq + 1e-5_f32).sqrt().recip();
            let y: [f32; 4] = [1.0 * rms, 2.0 * rms, 3.0 * rms, 4.0 * rms];
            vec![vec![to_bytes(&y)]]
        }),
    }
}
