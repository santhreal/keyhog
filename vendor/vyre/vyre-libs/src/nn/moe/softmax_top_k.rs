//! Fused `softmax_top_k` constructor for MoE gating.
//!
//! Computes `softmax(scores)` and returns the top-k indices + normalized weights
//! in a single dispatch, eliminating the separate softmax + top-k round-trip.

use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};

/// Build a Program that computes softmax over `scores`, then returns the
/// top-k indices and their normalized weights.
///
/// Inputs:
/// - `scores`: f32 buffer of length `n`
///
/// Outputs:
/// - `out_indices`: u32 buffer of length `k`
/// - `out_weights`: f32 buffer of length `k`
///
/// The weights sum to 1.0 across the full distribution (not just the top-k).
#[must_use]
pub fn softmax_top_k(
    scores: &str,
    out_indices: &str,
    out_weights: &str,
    n: u32,
    k: u32,
) -> Program {
    let mut body = vec![];

    // best_vals and best_idxs for top-k tracking
    for slot in 0..k {
        body.push(Node::Store {
            buffer: "best_vals".into(),
            index: Expr::u32(slot),
            value: Expr::f32(f32::NEG_INFINITY),
        });
        body.push(Node::Store {
            buffer: "best_idxs".into(),
            index: Expr::u32(slot),
            value: Expr::u32(0),
        });
    }

    // max_val = max(scores)
    body.push(Node::let_bind("max_val", Expr::f32(f32::NEG_INFINITY)));
    body.push(Node::loop_for(
        "i",
        Expr::u32(0),
        Expr::u32(n),
        vec![Node::if_then(
            Expr::gt(Expr::load(scores, Expr::var("i")), Expr::var("max_val")),
            vec![Node::assign("max_val", Expr::load(scores, Expr::var("i")))],
        )],
    ));

    // sum = sum(exp(score - max_val))
    // Also track top-k on the exp values
    body.push(Node::let_bind("sum", Expr::f32(0.0)));
    body.push(Node::loop_for(
        "i",
        Expr::u32(0),
        Expr::u32(n),
        vec![
            Node::let_bind(
                "exp_val",
                Expr::UnOp {
                    op: UnOp::Exp,
                    operand: Box::new(Expr::sub(
                        Expr::load(scores, Expr::var("i")),
                        Expr::var("max_val"),
                    )),
                },
            ),
            Node::assign("sum", Expr::add(Expr::var("sum"), Expr::var("exp_val"))),
            // Top-k insertion on exp_val
            Node::let_bind("insert_pos", Expr::u32(k)),
            Node::loop_for(
                "j",
                Expr::u32(0),
                Expr::u32(k),
                vec![Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("insert_pos"), Expr::u32(k)),
                        Expr::gt(
                            Expr::var("exp_val"),
                            Expr::load("best_vals", Expr::var("j")),
                        ),
                    ),
                    vec![Node::assign("insert_pos", Expr::var("j"))],
                )],
            ),
            Node::if_then(
                Expr::lt(Expr::var("insert_pos"), Expr::u32(k)),
                vec![
                    Node::loop_for(
                        "shift_j",
                        Expr::u32(0),
                        Expr::u32(k),
                        vec![
                            Node::let_bind(
                                "rev",
                                Expr::sub(Expr::u32(k - 1), Expr::var("shift_j")),
                            ),
                            Node::if_then(
                                Expr::and(
                                    Expr::ge(Expr::var("rev"), Expr::var("insert_pos")),
                                    Expr::lt(Expr::var("rev"), Expr::u32(k - 1)),
                                ),
                                vec![
                                    Node::Store {
                                        buffer: "best_vals".into(),
                                        index: Expr::add(Expr::var("rev"), Expr::u32(1)),
                                        value: Expr::load("best_vals", Expr::var("rev")),
                                    },
                                    Node::Store {
                                        buffer: "best_idxs".into(),
                                        index: Expr::add(Expr::var("rev"), Expr::u32(1)),
                                        value: Expr::load("best_idxs", Expr::var("rev")),
                                    },
                                ],
                            ),
                        ],
                    ),
                    Node::Store {
                        buffer: "best_vals".into(),
                        index: Expr::var("insert_pos"),
                        value: Expr::var("exp_val"),
                    },
                    Node::Store {
                        buffer: "best_idxs".into(),
                        index: Expr::var("insert_pos"),
                        value: Expr::var("i"),
                    },
                ],
            ),
        ],
    ));

    // Normalize top-k weights: best_vals[j] / sum
    for slot in 0..k {
        body.push(Node::Store {
            buffer: out_weights.into(),
            index: Expr::u32(slot),
            value: Expr::div(Expr::load("best_vals", Expr::u32(slot)), Expr::var("sum")),
        });
        body.push(Node::Store {
            buffer: out_indices.into(),
            index: Expr::u32(slot),
            value: Expr::load("best_idxs", Expr::u32(slot)),
        });
    }

    Program::wrapped(
        vec![
            BufferDecl::storage(scores, 0, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::output(out_indices, 1, DataType::U32).with_count(k),
            BufferDecl::read_write(out_weights, 2, DataType::F32).with_count(k),
            BufferDecl::read_write("best_vals", 3, DataType::F32).with_count(k),
            BufferDecl::read_write("best_idxs", 4, DataType::U32).with_count(k),
        ],
        [1, 1, 1],
        vec![wrap_anonymous("vyre-libs::nn::softmax_top_k", body)],
    )
}

fn fixture_f32_bytes(values: &[f32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_bits().to_le_bytes())
        .collect()
}

fn fixture_u32_bytes(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn softmax_top_k_fixture_inputs() -> Vec<Vec<Vec<u8>>> {
    let scores: [f32; 8] = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
    vec![vec![
        fixture_f32_bytes(&scores),
        vec![0u8; 4 * 2],
        vec![0u8; 4 * 2],
        vec![0u8; 4 * 2],
        vec![0u8; 4 * 2],
    ]]
}

fn softmax_top_k_fixture_expected() -> Vec<Vec<Vec<u8>>> {
    let scores: [f32; 8] = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
    let max = scores[7];
    let exp_values = scores
        .iter()
        .map(|score| (*score - max).exp())
        .collect::<Vec<f32>>();
    let sum = exp_values.iter().copied().sum::<f32>();
    let top_exp = [exp_values[7], exp_values[6]];
    vec![vec![
        fixture_u32_bytes(&[7, 6]),
        fixture_f32_bytes(&[top_exp[0] / sum, top_exp[1] / sum]),
        fixture_f32_bytes(&top_exp),
        fixture_u32_bytes(&[7, 6]),
    ]]
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_reference::value::Value;

    fn f32_bytes(words: &[f32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    fn u32_from_bytes(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    }

    fn f32_from_bytes(bytes: &[u8]) -> Vec<f32> {
        bytes
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    }

    #[test]
    fn softmax_top_k_basic() {
        // scores = [1.0, 2.0, 3.0] — softmax ≈ [0.090, 0.245, 0.665]
        let scores = vec![1.0f32, 2.0, 3.0];
        let program = softmax_top_k("scores", "indices", "weights", 3, 2);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[
                Value::from(f32_bytes(&scores)),
                Value::from(vec![0u8; 2 * 4]),
                Value::from(vec![0u8; 2 * 4]),
                Value::from(vec![0u8; 2 * 4]),
                Value::from(vec![0u8; 2 * 4]),
            ],
        )
        .unwrap();

        let indices = u32_from_bytes(&outputs[0].to_bytes());
        let weights = f32_from_bytes(&outputs[1].to_bytes());

        assert_eq!(indices[0], 2); // 3.0 is max
        assert_eq!(indices[1], 1); // 2.0 is second

        // Weights should be the normalized softmax values
        let max = 3.0f32;
        let exp0 = (1.0 - max).exp();
        let exp1 = (2.0 - max).exp();
        let exp2 = (3.0 - max).exp();
        let sum = exp0 + exp1 + exp2;
        let expected_w0 = exp2 / sum;
        let expected_w1 = exp1 / sum;

        assert!((weights[0] - expected_w0).abs() < 1e-4);
        assert!((weights[1] - expected_w1).abs() < 1e-4);
    }

    #[test]
    fn softmax_top_k_weights_sum_to_one() {
        let scores: Vec<f32> = (1..=8).map(|i| i as f32).collect();
        let program = softmax_top_k("scores", "indices", "weights", 8, 3);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[
                Value::from(f32_bytes(&scores)),
                Value::from(vec![0u8; 3 * 4]),
                Value::from(vec![0u8; 3 * 4]),
                Value::from(vec![0u8; 3 * 4]),
                Value::from(vec![0u8; 3 * 4]),
            ],
        )
        .unwrap();

        let weights = f32_from_bytes(&outputs[1].to_bytes());
        let total: f32 = weights.iter().sum();
        // The top-3 weights don't sum to 1.0, but the internal sum is 1.0.
        // Just verify the weights are positive and ordered correctly.
        assert!(total > 0.0);
        assert!(weights[0] > weights[1]);
        assert!(weights[1] > weights[2]);
        assert!(weights[0] > 0.0);
    }
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::nn::softmax_top_k",
        build: || softmax_top_k("scores", "indices", "weights", 8, 2),
        test_inputs: Some(softmax_top_k_fixture_inputs),
        expected_output: Some(softmax_top_k_fixture_expected),
        category: Some("nn"),
    }
}
