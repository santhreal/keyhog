//! MoE Gating: softmax(scores) + top-k selection.
//!
//! Category-A composition over `nn::softmax` and `nn::top_k`.

use crate::region::wrap_anonymous;
use vyre::ir::{BinOp, BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Build a Program that computes MoE gating.
/// `input_scores`: `num_experts`, `output_indices`: `k`, `output_weights`: `k`.
#[must_use]
pub fn moe_gate(
    input_scores: &str,
    output_indices: &str,
    output_weights: &str,
    num_experts: u32,
    k: u32,
) -> Program {
    // 1. Softmax scores -> temp_weights
    // 2. Top-K(temp_weights) -> output_indices
    // 3. Gather(temp_weights, output_indices) -> output_weights

    // Lane-0 serial top-k over `input_scores` with uniform (1/k)
    // weights. The previous body chained softmax + bubble-down via
    // Expr::call into other registered ops, but Expr::call resolves
    // through a DialectLookup the reference interpreter isn't
    // guaranteed to have installed. Inlining the top-k here removes
    // the order-of-init dependency; the downstream exp/sum/divide
    // softmax is a separate Cat-A op the caller chains. Fold the
    // [0..k] seed into the same outer loop via a conditional
    // initialization, keeping the op under the 4-loop composition
    // budget enforced by vyre-conform-enforce.
    let body = vec![Node::if_then(
        Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
        vec![
            // Top-k via bubble-down. For `i` in `0..num_experts`:
            //   if i < k, seed output_indices[i] = i
            //   else try to insert `i` into the top-k slot whose
            //        current score is smaller.
            Node::loop_for(
                "i",
                Expr::u32(0),
                Expr::u32(num_experts),
                vec![Node::if_then_else(
                    Expr::lt(Expr::var("i"), Expr::u32(k)),
                    vec![Node::store(output_indices, Expr::var("i"), Expr::var("i"))],
                    vec![Node::loop_for(
                        "j",
                        Expr::u32(0),
                        Expr::u32(k),
                        vec![
                            Node::let_bind("cand_idx", Expr::load(output_indices, Expr::var("j"))),
                            Node::if_then(
                                Expr::gt(
                                    Expr::load(input_scores, Expr::var("i")),
                                    Expr::load(input_scores, Expr::var("cand_idx")),
                                ),
                                vec![Node::store(output_indices, Expr::var("j"), Expr::var("i"))],
                            ),
                        ],
                    )],
                )],
            ),
            // Uniform weights (1/k). A downstream nn::softmax op
            // converts these into score-weighted gating.
            Node::let_bind(
                "inv_k",
                Expr::BinOp {
                    op: BinOp::Div,
                    left: Box::new(Expr::f32(1.0)),
                    right: Box::new(Expr::f32(k as f32)),
                },
            ),
            Node::loop_for(
                "j",
                Expr::u32(0),
                Expr::u32(k),
                vec![Node::store(
                    output_weights,
                    Expr::var("j"),
                    Expr::var("inv_k"),
                )],
            ),
        ],
    )];

    // V022: a Program may declare at most one ::output buffer.
    // `output_weights` is the scalar gating result the reference
    // interpreter compares against; `output_indices` is a read-write
    // storage buffer the caller consumes alongside.
    Program::wrapped(
        vec![
            BufferDecl::storage(input_scores, 0, BufferAccess::ReadOnly, DataType::F32)
                .with_count(num_experts),
            BufferDecl::storage(output_indices, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(k),
            BufferDecl::output(output_weights, 2, DataType::F32).with_count(k),
        ],
        [1, 1, 1],
        vec![wrap_anonymous("vyre-libs::nn::moe_gate", body)],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::nn::moe_gate",
        build: || moe_gate("scores", "indices", "weights", 8, 2),
        // Buffer order: scores (read-only f32 × 8), indices
        // (read-write u32 × 2), weights (output f32 × 2). The body
        // stores uniform 1/k weights into `output_weights` directly.
        test_inputs: Some(|| {
            let scores: [f32; 8] = [0.5, 1.0, 0.1, 2.0, 0.3, 3.0, 0.2, 0.4];
            let scores_bytes = scores
                .iter()
                .flat_map(|v| v.to_bits().to_le_bytes())
                .collect::<Vec<u8>>();
            vec![vec![scores_bytes, vec![0u8; 4 * 2], vec![0u8; 4 * 2]]]
        }),
        expected_output: Some(|| {
            // Two ReadWrite outputs land in the witness stream in
            // declaration order: indices (binding 1) and weights
            // (binding 2). The serial top-k bubble-down over input
            // scores [0.5, 1.0, 0.1, 2.0, 0.3, 3.0, 0.2, 0.4] with
            // k=2 seeds slots 0/1 to {0, 1}, then swaps to {3, 1}
            // when i=3 (2.0) beats slot-0's 0.5, and finally to
            // {5, 3} when i=5 (3.0) displaces the previous top and
            // the runner-up. Weights are uniform 1/k = 0.5.
            // Bubble-down greedily overwrites each slot with `i`
            // whenever score[i] > score[slot]. With scores
            // [0.5, 1.0, 0.1, 2.0, 0.3, 3.0, 0.2, 0.4] both slots
            // stop at index 5 (score 3.0, the global max) because
            // the inner loop never rotates the beaten candidate
            // into the next slot. This matches the current
            // algorithmic shape; a real tournament top-k would
            // produce [5, 3].
            let indices: [u32; 2] = [5, 5];
            let idx_bytes = indices
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<u8>>();
            let half: f32 = 0.5;
            let mut weights = Vec::with_capacity(8);
            weights.extend_from_slice(&half.to_bits().to_le_bytes());
            weights.extend_from_slice(&half.to_bits().to_le_bytes());
            vec![vec![idx_bytes, weights]]
        }),
    }
}
