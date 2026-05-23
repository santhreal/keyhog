//! Fused `linear_silu` constructor — Linear + SiLU activation in one
//! GPU dispatch.
//!
//! ROADMAP H5 — GEMM + bias + activation fusion. Companion to
//! `linear_relu`; computes `out[i] = silu(sum_k x[k] * w[k, i] + b[i])`
//! where `silu(z) = z / (1 + exp(-z))`.
//!
//! Without this fused variant, the same effect requires two
//! dispatches (linear, then silu) with an intermediate buffer
//! materialising the linear output to global memory only to be
//! re-read by silu. The fused variant keeps the matmul accumulator
//! in registers through the activation, halving the global memory
//! traffic.
//!
//! Soundness: numerically equivalent to `linear` followed by `silu`
//! because the activation is element-wise and depends only on the
//! per-output-row accumulator value.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};

use crate::region::wrap_anonymous;

/// Build a Program that computes `out[i] = silu(sum_k x[k] * w[k, i] + b[i])`.
///
/// Fused variant of `linear` followed by SiLU activation.
///
/// # Errors
/// Returns `Err` when `in_dim == 0` or `out_dim == 0`.
pub fn linear_silu(
    x: &str,
    w: &str,
    b: &str,
    out: &str,
    in_dim: u32,
    out_dim: u32,
) -> Result<Program, String> {
    if in_dim == 0 {
        return Err("Fix: linear_silu in_dim=0 is invalid: empty reduction".to_string());
    }
    if out_dim == 0 {
        return Err("Fix: linear_silu out_dim=0 is invalid: empty output".to_string());
    }
    let weight_count = in_dim.checked_mul(out_dim).ok_or_else(|| {
        "Fix: linear_silu in_dim*out_dim overflows u32; reduce dimensions.".to_string()
    })?;
    let i = Expr::var("i");
    // sigmoid(acc) = 1.0 / (1.0 + exp(-acc))
    let sigmoid_acc = Expr::div(
        Expr::f32(1.0),
        Expr::add(
            Expr::f32(1.0),
            Expr::UnOp {
                op: UnOp::Exp,
                operand: Box::new(Expr::UnOp {
                    op: UnOp::Negate,
                    operand: Box::new(Expr::var("acc")),
                }),
            },
        ),
    );
    let silu_acc = Expr::mul(Expr::var("acc"), sigmoid_acc);
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
                    value: silu_acc,
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
        vec![wrap_anonymous("vyre-libs::nn::linear_silu", body)],
    ))
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::nn::linear_silu",
        build: || {
            linear_silu("x", "w", "b", "out", 4, 4).unwrap_or_else(|error| {
                crate::builder::invalid_output_program(
                    "vyre-libs::nn::linear_silu",
                    "out",
                    DataType::F32,
                    error,
                )
            })
        },
        test_inputs: Some(|| {
            let f32_bytes = |words: &[f32]| {
                words.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>()
            };
            let x = f32_bytes(&(0..4).map(|i| i as f32).collect::<Vec<_>>());
            let w = f32_bytes(&(0..16).map(|i| i as f32).collect::<Vec<_>>());
            let bias = f32_bytes(&[0.0, 0.0, 0.0, 0.0]);
            vec![vec![x, w, bias]]
        }),
        expected_output: Some(|| {
            // linear: x=[0,1,2,3], w[k,i] = k*4+i, b=[0,0,0,0]
            // out[i] = sum_k x[k] * w[k, i]
            //        = 0*i + 1*(4+i) + 2*(8+i) + 3*(12+i)
            //        = (4 + 8*2 + 12*3) + (1 + 2 + 3) * i
            //        = (4 + 16 + 36) + 6 * i
            //        = 56 + 6*i
            // Then silu(z) = z / (1 + exp(-z))
            let acc: Vec<f32> = (0..4).map(|i| 56.0 + 6.0 * i as f32).collect();
            let silu: Vec<f32> = acc.iter().map(|z| z / (1.0 + (-z).exp())).collect();
            let bytes = silu
                .iter()
                .flat_map(|v| v.to_bits().to_le_bytes())
                .collect::<Vec<u8>>();
            vec![vec![bytes]]
        }),
        category: Some("nn"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_reference::value::Value;

    fn f32_bytes(values: &[f32]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect()
    }

    fn decode(bytes: &[u8]) -> Vec<f32> {
        bytes
            .chunks_exact(4)
            .map(|chunk| f32::from_le_bytes(chunk.try_into().unwrap()))
            .collect()
    }

    fn silu_scalar(z: f32) -> f32 {
        z / (1.0 + (-z).exp())
    }

    /// `linear_silu` matches `linear` followed by element-wise silu
    /// when both are evaluated through the reference interpreter.
    #[test]
    fn linear_silu_matches_linear_plus_silu_reference() {
        let in_dim = 4u32;
        let out_dim = 4u32;
        let x: Vec<f32> = (0..in_dim).map(|i| i as f32).collect();
        let w: Vec<f32> = (0..in_dim * out_dim).map(|i| i as f32 * 0.1).collect();
        let bias = vec![0.5, -0.25, 1.0, 0.0];
        let prog = linear_silu("x", "w", "b", "out", in_dim, out_dim).expect("build");
        let outputs = vyre_reference::reference_eval(
            &prog,
            &[
                Value::from(f32_bytes(&x)),
                Value::from(f32_bytes(&w)),
                Value::from(f32_bytes(&bias)),
                Value::from(vec![0u8; (out_dim as usize) * 4]),
            ],
        )
        .expect("Fix: linear_silu must execute in the reference interpreter.");
        let actual = decode(&outputs[0].to_bytes());
        let expected: Vec<f32> = (0..out_dim as usize)
            .map(|i| {
                let acc = bias[i]
                    + (0..in_dim as usize)
                        .map(|k| x[k] * w[k * out_dim as usize + i])
                        .sum::<f32>();
                silu_scalar(acc)
            })
            .collect();
        for (a, e) in actual.iter().zip(expected.iter()) {
            assert!((a - e).abs() <= 1.0e-5, "{a} != {e}");
        }
    }

    /// `linear_silu(0, _)` rejects the empty reduction.
    #[test]
    fn linear_silu_rejects_empty_in_dim() {
        let err =
            linear_silu("x", "w", "b", "out", 0, 4).expect_err("Fix: empty reduction must error");
        assert!(err.contains("in_dim=0"));
    }

    /// `linear_silu(_, 0)` rejects empty output.
    #[test]
    fn linear_silu_rejects_empty_out_dim() {
        let err =
            linear_silu("x", "w", "b", "out", 4, 0).expect_err("Fix: empty output must error");
        assert!(err.contains("out_dim=0"));
    }
}
