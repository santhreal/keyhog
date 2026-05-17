//! Fused `linear_relu` constructor.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::region::wrap_anonymous;

/// Build a Program that computes `out[i] = max(0, sum_k x[k] * w[k, i] + b[i])`.
///
/// Fused variant of `linear` followed by ReLU.
///
/// # Errors
/// Returns `Err` when `in_dim == 0`.
pub fn linear_relu(
    x: &str,
    w: &str,
    b: &str,
    out: &str,
    in_dim: u32,
    out_dim: u32,
) -> Result<Program, String> {
    if in_dim == 0 {
        return Err("Fix: linear_relu in_dim=0 is invalid: empty reduction".to_string());
    }
    if out_dim == 0 {
        return Err("Fix: linear_relu out_dim=0 is invalid: empty output".to_string());
    }
    let weight_count = in_dim.checked_mul(out_dim).ok_or_else(|| {
        "Fix: linear_relu in_dim*out_dim overflows u32; reduce dimensions.".to_string()
    })?;
    let i = Expr::var("i");
    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::u32(out_dim)),
            vec![
                Node::let_bind("acc", Expr::load(b, i.clone())),
                Node::loop_for(
                    "k",
                    Expr::u32(0),
                    Expr::u32(in_dim),
                    vec![Node::assign(
                        "acc",
                        Expr::add(
                            Expr::var("acc"),
                            Expr::mul(
                                Expr::load(x, Expr::var("k")),
                                Expr::load(
                                    w,
                                    Expr::add(
                                        Expr::mul(Expr::var("k"), Expr::u32(out_dim)),
                                        i.clone(),
                                    ),
                                ),
                            ),
                        ),
                    )],
                ),
                Node::Store {
                    buffer: out.into(),
                    index: i,
                    value: Expr::max(Expr::f32(0.0), Expr::var("acc")),
                },
            ],
        ),
    ];
    Ok(Program::wrapped(
        vec![
            BufferDecl::storage(x, 0, BufferAccess::ReadOnly, DataType::F32).with_count(in_dim),
            BufferDecl::storage(w, 1, BufferAccess::ReadOnly, DataType::F32)
                .with_count(weight_count),
            BufferDecl::storage(b, 2, BufferAccess::ReadOnly, DataType::F32).with_count(out_dim),
            BufferDecl::output(out, 3, DataType::F32).with_count(out_dim),
        ],
        [64, 1, 1],
        vec![wrap_anonymous("vyre-libs::nn::linear_relu", body)],
    ))
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::nn::linear_relu",
        build: || {
            linear_relu("x", "w", "b", "out", 4, 4).unwrap_or_else(|error| {
                crate::builder::invalid_output_program(
                    "vyre-libs::nn::linear_relu",
                    "out",
                    DataType::F32,
                    error,
                )
            })
        },
        test_inputs: Some(|| {
            let f32_bytes = |words: &[f32]| words.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            let x = f32_bytes(&(0..4).map(|i| i as f32).collect::<Vec<_>>());
            let w = f32_bytes(&(0..16).map(|i| i as f32).collect::<Vec<_>>());
            let bias = f32_bytes(&[0.0, 0.0, 0.0, 0.0]);
            vec![vec![x, w, bias, vec![0u8; 4 * 4]]]
        }),
        expected_output: Some(|| {
            let f32_bytes = |words: &[f32]| words.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![f32_bytes(&[56.0, 62.0, 68.0, 74.0])]]
        }),
    }
}
