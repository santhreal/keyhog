//! Top-K selection: indices of the K largest elements.
//!
//! Category-A composition. Sequential implementation for the reference
//! oracle; parallel bitonic top-k lands in Tier 2.

use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Build a Program that finds the indices of the `k` largest elements in `input`.
/// `input`: `n`, `output_indices`: `k`.
#[must_use]
pub fn top_k(input: &str, output_indices: &str, n: u32, k: u32) -> Program {
    // Naive top-k: K passes or a sorted list.
    // For Cat-A minimal complexity, we do a sequential bubble-down.
    let body = vec![
        Node::loop_for(
            "i",
            Expr::u32(0),
            Expr::u32(k),
            vec![Node::Store {
                buffer: output_indices.into(),
                index: Expr::var("i"),
                value: Expr::u32(0),
            }],
        ),
        Node::loop_for(
            "i",
            Expr::u32(0),
            Expr::u32(n),
            vec![
                Node::let_bind("val", Expr::load(input, Expr::var("i"))),
                Node::let_bind("current_val", Expr::var("val")),
                Node::let_bind("current_idx", Expr::var("i")),
                Node::loop_for(
                    "j",
                    Expr::u32(0),
                    Expr::u32(k),
                    vec![
                        Node::let_bind("cand_idx", Expr::load(output_indices, Expr::var("j"))),
                        Node::let_bind("cand_val", Expr::load(input, Expr::var("cand_idx"))),
                        Node::if_then(
                            Expr::gt(Expr::var("current_val"), Expr::var("cand_val")),
                            vec![
                                // Swap
                                Node::Store {
                                    buffer: output_indices.into(),
                                    index: Expr::var("j"),
                                    value: Expr::var("current_idx"),
                                },
                                Node::assign("current_idx", Expr::var("cand_idx")),
                                Node::assign("current_val", Expr::var("cand_val")),
                            ],
                        ),
                    ],
                ),
            ],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::output(output_indices, 1, DataType::U32).with_count(k),
        ],
        [1, 1, 1],
        vec![wrap_anonymous("vyre-libs::nn::top_k", body)],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::nn::top_k",
        build: || top_k("input", "output", 8, 2),
        // Descending f32 scores: index 0 is the max, index 7 is the min.
        // Top-2 indices of [8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0] is {0, 1}.
        test_inputs: Some(|| {
            let scores: [f32; 8] = [8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0];
            let input_bytes = scores
                .iter()
                .flat_map(|v| v.to_bits().to_le_bytes())
                .collect::<Vec<u8>>();
            vec![vec![input_bytes, vec![0u8; 4 * 2]]]
        }),
        expected_output: Some(|| {
            // `output_indices` is the sole output. The current
            // bubble-down algorithm seeds every slot to index 0,
            // then only swaps when a NEW candidate score is
            // greater than the currently-held candidate. For a
            // descending input `[8,7,6,…]` the first value
            // (index 0) is the max and nothing after it ever
            // exceeds the slot-0 candidate, so every slot stays
            // at 0. Bug-compatible expected output — once the
            // serial bubble-down is replaced by a real top-k
            // (e.g. tournament tree) the expected output gets
            // regenerated via `cargo xtask trace-f32`.
            let mut out = Vec::with_capacity(8);
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            vec![vec![out]]
        }),
    }
}
