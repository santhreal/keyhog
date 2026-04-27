//! Linear layer: `y = x @ W + b`.
//!
//! Category A composition — matmul + element-wise add. Implemented
//! inline rather than by delegation so the Region has one clean body
//! the optimizer can fuse; a future `linear_tiled` variant can
//! delegate to `matmul_tiled` when it exists.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};

use crate::region::wrap_anonymous;

/// Build a Program that computes `out[i] = sum_k x[k] * w[k, i] + b[i]`.
///
/// Shapes: `x: [in_dim]`, `w: [in_dim, out_dim]`, `b: [out_dim]`,
/// `out: [out_dim]`. Workgroup `[64, 1, 1]` — each invocation handles
/// one output index.
///
/// # Errors
/// Returns `Err` when `in_dim == 0` (FINDING-V7-TEST-010-LINEAR).
pub fn linear(
    x: &str,
    w: &str,
    b: &str,
    out: &str,
    in_dim: u32,
    out_dim: u32,
) -> Result<Program, String> {
    if in_dim == 0 {
        return Err("Fix: linear in_dim=0 is invalid: empty reduction".to_string());
    }
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
                    value: Expr::var("acc"),
                },
            ],
        ),
    ];
    Ok(Program::wrapped(
        vec![
            BufferDecl::storage(x, 0, BufferAccess::ReadOnly, DataType::U32).with_count(in_dim),
            BufferDecl::storage(w, 1, BufferAccess::ReadOnly, DataType::U32).with_count(
                in_dim
                    .checked_mul(out_dim)
                    .expect("linear: in_dim * out_dim overflows u32 — see V7-CORR-007"),
            ),
            BufferDecl::storage(b, 2, BufferAccess::ReadOnly, DataType::U32).with_count(out_dim),
            BufferDecl::output(out, 3, DataType::U32).with_count(out_dim),
        ],
        [64, 1, 1],
        vec![wrap_anonymous("vyre-libs::nn::linear", body)],
    ))
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::nn::linear",
        build: || linear("x", "w", "b", "out", 4, 4).unwrap(),
        // V7-TEST-005: deterministic fixture for linear(4, 4).
        // Body indexes `w[k * out_dim + i]` (column-major per out_dim),
        // so for w = [0..16], out_dim = 4:
        //   out[i] = b[i] + sum_k x[k] * w[k*4 + i]
        // With x = [0, 1, 2, 3] and b = [0, 0, 0, 0]:
        //   out[0] = 0*0 + 1*4 + 2*8  + 3*12 =  4 + 16 + 36 = 56
        //   out[1] = 0*1 + 1*5 + 2*9  + 3*13 =  5 + 18 + 39 = 62
        //   out[2] = 0*2 + 1*6 + 2*10 + 3*14 =  6 + 20 + 42 = 68
        //   out[3] = 0*3 + 1*7 + 2*11 + 3*15 =  7 + 22 + 45 = 74
        test_inputs: Some(|| {
            let u32_bytes = |words: &[u32]| words.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            let x = u32_bytes(&(0..4).collect::<Vec<_>>());
            let w = u32_bytes(&(0..16).collect::<Vec<_>>());
            let bias = u32_bytes(&[0, 0, 0, 0]);
            vec![vec![x, w, bias, vec![0u8; 4 * 4]]]
        }),
        expected_output: Some(|| {
            let u32_bytes =
                |words: &[u32]| words.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![u32_bytes(&[56, 62, 68, 74])]]
        }),
    }
}

/// Build a Program that computes `out[i] = max(0, sum_k x[k] * w[k, i] + b[i])`.
///
/// Fused variant of `linear` followed by ReLU. Shapes and workgroup are
/// identical to [`linear`]; the only difference is the final `max(0, acc)`
/// applied before storing. All buffers use `F32` so the ReLU clipping is
/// semantically meaningful.
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
            BufferDecl::storage(w, 1, BufferAccess::ReadOnly, DataType::F32).with_count(
                in_dim
                    .checked_mul(out_dim)
                    .expect("linear_relu: in_dim * out_dim overflows u32 — see V7-CORR-007"),
            ),
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
        build: || linear_relu("x", "w", "b", "out", 4, 4).unwrap(),
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

#[cfg(test)]
mod tests {
    use vyre_reference::value::Value;

    use super::*;

    const TOLERANCE_ULP: u32 = 2;

    fn to_f32_bytes(words: &[f32]) -> Vec<u8> {
        words
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<u8>>()
    }

    fn bytes_to_f32(values: &[u8]) -> Vec<f32> {
        values
            .chunks_exact(4)
            .map(|chunk| {
                f32::from_le_bytes(
                    chunk
                        .try_into()
                        .expect("f32 output chunk is always 4 bytes"),
                )
            })
            .collect()
    }

    fn ordered_bits(value: f32) -> u32 {
        let bits = value.to_bits();
        if bits & 0x8000_0000 != 0 {
            !bits
        } else {
            bits | 0x8000_0000
        }
    }

    fn compare_ulp(a: &[f32], b: &[f32], n: u32, in_dim: u32, out_dim: u32) {
        assert_eq!(
            a.len(),
            b.len(),
            "rms_norm_linear parity output length mismatch n={n} in_dim={in_dim} out_dim={out_dim}: {} vs {}",
            a.len(),
            b.len()
        );

        for (lane, (lhs, rhs)) in a.iter().zip(b.iter()).enumerate() {
            if lhs.is_nan() || rhs.is_nan() {
                assert_eq!(
                    lhs.to_bits(),
                    rhs.to_bits(),
                    "NaN payload mismatch at lane {lane} n={n} in_dim={in_dim} out_dim={out_dim}"
                );
                continue;
            }
            let diff = ordered_bits(*lhs).abs_diff(ordered_bits(*rhs));
            assert!(
                diff <= TOLERANCE_ULP,
                "ULP mismatch at lane {lane} n={n} in_dim={in_dim} out_dim={out_dim}: lhs={lhs:?} rhs={rhs:?} diff={diff}"
            );
        }
    }

    fn case_data(_n: u32, in_dim: u32, out_dim: u32, eps: f32) -> (Vec<f32>, Vec<f32>, Vec<f32>) {
        let input = (0..in_dim)
            .map(|i| (i as f32 + 1.0) * if i % 2 == 0 { 0.37 } else { -0.41 })
            .collect::<Vec<_>>();
        let weights = (0..(in_dim * out_dim))
            .map(|i| (i as f32) * 0.011 + 0.23)
            .collect::<Vec<_>>();
        let bias = (0..out_dim)
            .map(|i| (i as f32) * 0.17 + eps)
            .collect::<Vec<_>>();
        (input, weights, bias)
    }

    fn linear_reference(
        input: &[f32],
        normalized: &[f32],
        weights: &[f32],
        bias: &[f32],
        out_dim: u32,
        in_dim: u32,
        n: u32,
        eps: f32,
    ) -> Vec<f32> {
        assert_eq!(
            normalized.len(),
            n as usize,
            "linear_reference must receive exactly n normalized values: got {} vs {}",
            normalized.len(),
            n
        );
        let inv_scale =
            1.0_f32 / ((normalized.iter().map(|v| v * v).sum::<f32>() / (n as f32)) + eps).sqrt();
        let mut output = bias.to_vec();
        for j in 0..out_dim as usize {
            let mut acc = output[j];
            for k in 0..in_dim as usize {
                acc += input[k] * inv_scale * weights[k * out_dim as usize + j];
            }
            output[j] = acc;
        }
        output
    }

    fn parity_case(n: u32, in_dim: u32, out_dim: u32) {
        let eps = 1e-5_f32;
        let (input, weights, bias) = case_data(n, in_dim, out_dim, eps);

        let fused = rms_norm_linear("input", "w", "b", "out", n, in_dim, out_dim, eps);
        let fused_inputs = vec![
            Value::from(to_f32_bytes(&input)),
            Value::from(to_f32_bytes(&weights)),
            Value::from(to_f32_bytes(&bias)),
            Value::from(vec![0u8; out_dim as usize * core::mem::size_of::<f32>()]),
        ];
        let fused_outputs = vyre_reference::reference_eval(&fused, &fused_inputs)
            .expect("fused rms_norm_linear must execute");
        let fused_out = bytes_to_f32(&fused_outputs[0].to_bytes());
        let normalized = &input[0..n as usize];
        let expected =
            linear_reference(&input, normalized, &weights, &bias, out_dim, in_dim, n, eps);
        compare_ulp(&fused_out, &expected, n, in_dim, out_dim);
    }

    #[test]
    fn parity_rms_norm_linear_matches_reference_three_sizes() {
        for (n, in_dim, out_dim) in [(4_u32, 4_u32, 4_u32), (16, 64, 16), (64, 128, 64)] {
            parity_case(n, in_dim, out_dim);
        }
    }
}

/// Build a Program that computes fused RMSNorm + Linear:
/// `y[j] = b[j] + Σ_k (x[k] / sqrt(mean(x^2) + eps)) * w[k, j]`.
/// `mean(x^2)` is computed over the first `n` elements; `k` in the matmul
/// ranges over `in_dim`.
///
/// Shapes:
/// - `x: [in_dim]`, `w: [in_dim, out_dim]` (row-major by `out_dim`),
///   `b: [out_dim]`, `out: [out_dim]`.
#[must_use]
pub fn rms_norm_linear(
    input: &str,
    w: &str,
    b: &str,
    out: &str,
    n: u32,
    in_dim: u32,
    out_dim: u32,
    eps: f32,
) -> Program {
    assert!(
        n <= in_dim,
        "Fix: rms_norm_linear requires n <= in_dim so RMS computes over prefix of x used by linear reduction. Got n={n}, in_dim={in_dim}"
    );
    let weight_count = in_dim
        .checked_mul(out_dim)
        .expect("rms_norm_linear: in_dim * out_dim overflows u32");

    let lane = Expr::var("lane");
    let k = Expr::var("k");

    let mean_sq = vec![
        Node::let_bind("sum_sq", Expr::f32(0.0)),
        Node::loop_for(
            "k",
            Expr::u32(0),
            Expr::u32(n),
            vec![Node::assign(
                "sum_sq",
                Expr::add(
                    Expr::var("sum_sq"),
                    Expr::mul(Expr::load(input, k.clone()), Expr::load(input, k.clone())),
                ),
            )],
        ),
        Node::Store {
            buffer: "inv_rms".into(),
            index: Expr::u32(0),
            value: Expr::UnOp {
                op: UnOp::InverseSqrt,
                operand: Box::new(Expr::add(
                    Expr::div(Expr::var("sum_sq"), Expr::f32(n as f32)),
                    Expr::f32(eps),
                )),
            },
        },
    ];

    let output_lane = vec![
        Node::let_bind("acc", Expr::load(b, lane.clone())),
        Node::let_bind("scale", Expr::load("inv_rms", Expr::u32(0))),
        Node::loop_for(
            "k",
            Expr::u32(0),
            Expr::u32(in_dim),
            vec![Node::assign(
                "acc",
                Expr::add(
                    Expr::var("acc"),
                    Expr::mul(
                        Expr::mul(Expr::load(input, k.clone()), Expr::var("scale")),
                        Expr::load(
                            w,
                            Expr::add(Expr::mul(k.clone(), Expr::u32(out_dim)), lane.clone()),
                        ),
                    ),
                ),
            )],
        ),
        Node::Store {
            buffer: out.into(),
            index: lane.clone(),
            value: Expr::var("acc"),
        },
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::F32).with_count(in_dim),
            BufferDecl::storage(w, 1, BufferAccess::ReadOnly, DataType::F32)
                .with_count(weight_count),
            BufferDecl::storage(b, 2, BufferAccess::ReadOnly, DataType::F32).with_count(out_dim),
            BufferDecl::workgroup("inv_rms", 1, DataType::F32),
            BufferDecl::output(out, 4, DataType::F32).with_count(out_dim),
        ],
        [64, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::nn::rms_norm_linear",
            vec![
                Node::let_bind("lane", Expr::InvocationId { axis: 0 }),
                Node::if_then(Expr::eq(lane.clone(), Expr::u32(0)), mean_sq),
                Node::barrier(),
                Node::if_then(Expr::lt(lane.clone(), Expr::u32(out_dim)), output_lane),
            ],
        )],
    )
    .with_entry_op_id("vyre-libs::nn::rms_norm_linear")
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::nn::rms_norm_linear",
        build: || rms_norm_linear("input", "w", "b", "out", 4, 4, 4, 1e-5),
        test_inputs: Some(|| {
            let to_bytes = |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            let input = [1.0_f32, 2.0, 3.0, 4.0];
            let weights = (0u32..16u32).map(|v| v as f32).collect::<Vec<_>>();
            vec![vec![
                to_bytes(&input),
                to_bytes(&weights),
                vec![0u8; 4 * 4],
                vec![0u8; 4 * 4],
            ]]
        }),
        expected_output: Some(|| {
            let to_bytes = |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            let input = [1.0_f32, 2.0, 3.0, 4.0];
            let eps = 1e-5_f32;
            let inv_scale =
                1.0_f32 / (input.iter().map(|v| v * v).sum::<f32>() / 4.0_f32 + eps).sqrt();
            let mut out = Vec::with_capacity(4);
            for j in 0..4usize {
                let mut acc = 0.0_f32;
                for k in 0..4usize {
                    acc += input[k] * inv_scale * (k * 4 + j) as f32;
                }
                out.push(acc);
            }
            vec![vec![to_bytes(&out)]]
        }),
    }
}

#[cfg(test)]
mod linear_relu_tests {
    use vyre_reference::value::Value;

    use super::linear_relu;

    #[test]
    fn linear_relu_parity_with_sequential_linear_plus_relu() {
        let dims = [(4, 8), (16, 32), (64, 128), (128, 256), (256, 512)];
        let mut rng = 0x1234_5678_u64;
        let mut next_f32 = || {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            f32::from_bits((rng >> 32) as u32)
        };

        for (in_dim, out_dim) in dims {
            let x: Vec<f32> = (0..in_dim).map(|_| next_f32()).collect();
            let w: Vec<f32> = (0..in_dim * out_dim).map(|_| next_f32()).collect();
            let b: Vec<f32> = (0..out_dim).map(|_| next_f32()).collect();

            let x_bytes = x.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            let w_bytes = w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            let b_bytes = b.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();

            // Run fused linear_relu
            let fused = linear_relu("x", "w", "b", "out", in_dim, out_dim).unwrap();
            let fused_out = vyre_reference::reference_eval(
                &fused,
                &[
                    Value::from(x_bytes.clone()),
                    Value::from(w_bytes.clone()),
                    Value::from(b_bytes.clone()),
                    Value::from(vec![0u8; (out_dim as usize) * 4]),
                ],
            )
            .unwrap();

            // Compute unfused reference: linear then relu
            let mut expected = vec![0.0f32; out_dim as usize];
            for i in 0..out_dim {
                let mut acc = b[i as usize];
                for k in 0..in_dim {
                    acc += x[k as usize] * w[(k * out_dim + i) as usize];
                }
                expected[i as usize] = acc.max(0.0);
            }
            let expected_bytes: Vec<u8> = expected.iter().flat_map(|v| v.to_le_bytes()).collect();

            assert_eq!(
                fused_out[0].to_bytes(),
                expected_bytes,
                "linear_relu must match linear followed by relu for (in_dim={in_dim}, out_dim={out_dim})"
            );
        }
    }
}
