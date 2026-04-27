//! Quest-style Query-Aware KV Paging.
//!
//! Only the "which pages are critical" decision — a pure score-and-select
//! pass. Scoring is `dot(query, page_metadata[p])` for each page; the
//! top-`k` highest-scoring pages are emitted, in descending order, into
//! `io_queue[0..k]`. The remainder of `io_queue` is zero-filled on the
//! first pass so the output is deterministic.
//!
//! Downstream DMA / `AsyncLoad` is the scheduler's job — this op only
//! tells the scheduler which pages to fetch.

use crate::region::{wrap_anonymous, wrap_child};
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre_foundation::ir::model::expr::GeneratorRef;
use vyre_primitives::nn::quest_paging_passes::{
    quest_score_pages_body, quest_select_top_k_body, quest_zero_fill_body, QUEST_SCORE_PAGES_OP_ID,
    QUEST_SELECT_TOP_K_OP_ID, QUEST_ZERO_FILL_OP_ID,
};

const OP_ID: &str = "vyre-libs::nn::attention::quest_paging";

// Naga / WGSL rejects `inf` and NaN literals, so the argmax sentinel
// must be a large-magnitude finite value. `f32::MIN` is the most
// negative finite f32 — strictly less than every reachable dot-product
// score when `query` and `page_metadata` are finite inputs.
const SCORE_SENTINEL: f32 = f32::MIN;

/// Build a Program that writes the top-`k` page indices (by query
/// similarity) into `io_queue`.
///
/// Buffers:
/// - `query` (ReadOnly, F32, `d_head`)
/// - `page_metadata` (ReadOnly, F32, `num_pages * d_head`)
/// - `scores` (ReadWrite, F32, `num_pages`) — per-page dot score scratch
/// - `io_queue` (ReadWrite, U32, `num_pages`) — index 0..k holds top-k,
///    rest holds 0
#[must_use]
pub fn quest_paging(
    query: &str,
    page_metadata: &str,
    scores: &str,
    io_queue: &str,
    num_pages: u32,
    k: u32,
    d_head: u32,
) -> Program {
    // Single-invocation serial body so top-k selection is deterministic
    // regardless of backend. `num_pages` is small (typically ≤ 512 in
    // the KV-paging regime) so the O(num_pages · k) top-k is fine.
    let parent = GeneratorRef {
        name: OP_ID.to_string(),
    };
    let t = Expr::InvocationId { axis: 0 };
    let body = vec![
        // 1. Zero-fill io_queue so unused slots are deterministic.
        wrap_child(
            QUEST_ZERO_FILL_OP_ID,
            parent.clone(),
            quest_zero_fill_body(io_queue, num_pages),
        ),
        // 2. Score every page.
        wrap_child(
            QUEST_SCORE_PAGES_OP_ID,
            parent.clone(),
            quest_score_pages_body(query, page_metadata, scores, num_pages, d_head),
        ),
        Node::barrier(),
        // 3. Select top-k pages by repeated argmax. Each iteration sweeps
        //    `scores`, picks the current maximum, writes its index into
        //    `io_queue[j]`, then marks that slot with SCORE_SENTINEL so the
        //    next iteration skips it.
        wrap_child(
            QUEST_SELECT_TOP_K_OP_ID,
            parent,
            vec![Node::if_then(
                Expr::eq(t.clone(), Expr::u32(0)),
                quest_select_top_k_body(scores, io_queue, num_pages, k, SCORE_SENTINEL),
            )],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(query, 0, BufferAccess::ReadOnly, DataType::F32).with_count(d_head),
            BufferDecl::storage(page_metadata, 1, BufferAccess::ReadOnly, DataType::F32)
                .with_count(num_pages * d_head),
            BufferDecl::storage(scores, 2, BufferAccess::ReadWrite, DataType::F32)
                .with_count(num_pages),
            BufferDecl::storage(io_queue, 3, BufferAccess::ReadWrite, DataType::U32)
                .with_count(num_pages),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(OP_ID, body)],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || quest_paging("q", "meta", "scores", "io", 4, 2, 2),
        test_inputs: Some(|| {
            let to_f32_bytes =
                |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // num_pages=4, d_head=2, k=2.
            // query = [1.0, 0.0]
            // page_metadata[p, d]: page 0=[0, 0], page 1=[1, 0], page 2=[2, 0], page 3=[0.5, 0].
            // scores[p] = dot(query, page_metadata[p]) = page_metadata[p, 0].
            //   → scores = [0.0, 1.0, 2.0, 0.5].
            // Top-2 by descending score → indices [2, 1].
            vec![vec![
                to_f32_bytes(&[1.0, 0.0]),
                to_f32_bytes(&[0.0, 0.0, 1.0, 0.0, 2.0, 0.0, 0.5, 0.0]),
                vec![0u8; 4 * 4],
                vec![0u8; 4 * 4],
            ]]
        }),
        expected_output: Some(|| {
            let to_f32_bytes =
                |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            let to_u32_bytes =
                |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // scores after selection: only slots that were picked
            // (indices 2 and 1) are overwritten with SCORE_SENTINEL.
            // Indices 0 and 3 retain their pass-1 dot-product scores.
            let scores = [0.0, SCORE_SENTINEL, SCORE_SENTINEL, 0.5];
            // io_queue[0..2] = [2, 1] (top-2 in descending score).
            // io_queue[2..4] = [0, 0] (zero-filled on pass 1).
            let io_queue = [2u32, 1, 0, 0];
            vec![vec![to_f32_bytes(&scores), to_u32_bytes(&io_queue)]]
        }),
    }
}
