//! Adaptive CSR / dense-bitmatrix traversal (G4).
//!
//! # What this is
//!
//! `csr_forward_traverse` is ideal when the BFS frontier is sparse
//! (<~5% of nodes). When the frontier saturates, a dense-bitmatrix
//! step (adjacency × frontier) wins — each tile's adjacency bitrow
//! × its frontier bitset is one vectorised OR over a pair of 32-bit
//! words, with contiguous DRAM access patterns that outrun CSR.
//!
//! This primitive picks which representation to use per tile. The
//! selector is host logic; given the frontier popcount as a fraction
//! of `node_count`, choose CSR or dense:
//!
//! ```text
//!   density_pct = 100 * popcount(frontier_in) / node_count
//!   if density_pct >= DENSE_THRESHOLD_PCT: dense step
//!   else: CSR step
//! ```
//!
//! The dense step is a bitmatrix multiply:
//!
//! ```text
//!   for dst in 0..node_count:
//!     if (adj_row[dst] & frontier_in) != 0:
//!       frontier_out[dst] = 1
//! ```
//!
//! where `adj_row[dst]` is a bitset over source-node predecessors
//! (reverse adjacency, encoded as one row of `bitset_words(node_count)`
//! u32s per destination node).
//!
//! # Buffers
//!
//! - `frontier_in`  — ReadOnly, packed bitset, `bitset_words(n)` u32.
//! - `frontier_out` — ReadWrite, same shape.
//! - `adj_rows_dense` — ReadOnly, `node_count × bitset_words(n)` u32.
//!   Row `d` is the bitset of predecessors of node `d`.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::bitset::bitset_words;

/// Density threshold (percent). Tiles with ≥ this fraction of
/// frontier bits set use the dense-bitmatrix step; below it, CSR.
/// 25% is the empirical crossover on NVIDIA Ada+ / AMD RDNA3.
pub const DENSE_THRESHOLD_PCT: u32 = 25;

/// Canonical op id for the dense step.
pub const OP_ID: &str = "vyre-primitives::graph::adaptive_traverse_dense";

/// Canonical input-frontier buffer name.
pub const NAME_FRONTIER_IN: &str = "adap_frontier_in";
/// Canonical output-frontier buffer name.
pub const NAME_FRONTIER_OUT: &str = "adap_frontier_out";
/// Canonical dense adjacency-row buffer name.
pub const NAME_ADJ_ROWS_DENSE: &str = "adap_adj_rows_dense";

/// Host-side density probe. Returns `true` iff
/// `popcount(frontier_in) / node_count ≥ DENSE_THRESHOLD_PCT / 100`.
///
/// `frontier_in` is the packed bitset; `node_count` is the total
/// number of nodes (not necessarily a multiple of 32). Integer-only
/// comparison — no floating-point rounding surprises.
#[must_use]
pub fn should_use_dense(frontier_in: &[u32], node_count: u32) -> bool {
    if node_count == 0 {
        return false;
    }
    let popcount: u32 = frontier_in.iter().map(|w| w.count_ones()).sum();
    (popcount as u64) * 100 >= (DENSE_THRESHOLD_PCT as u64) * (node_count as u64)
}

/// Build the GPU Program for one dense step. Invocation `d`
/// computes `frontier_out[d] = any bit of (adj_rows[d] &
/// frontier_in) is set`.
#[must_use]
pub fn adaptive_dense_step(
    frontier_in: &str,
    frontier_out: &str,
    adj_rows_dense: &str,
    node_count: u32,
) -> Program {
    let words = bitset_words(node_count);
    // PHASE7_GRAPH C1: the adjacency buffer size is `node_count *
    // words`. A u32 × u32 multiply wraps silently for non-trivial
    // inputs (e.g. node_count ≈ 400k, words ≈ 12.5k wraps past
    // u32::MAX), producing a tiny buffer and catastrophic OOB
    // reads/writes. Check in u64 first and refuse programs we
    // cannot represent faithfully.
    let adj_count = u64::from(node_count).checked_mul(u64::from(words)).expect(
        "adaptive_dense_step: node_count * words overflows u64 — impossible on 32-bit u32 inputs",
    );
    assert!(
        adj_count <= u64::from(u32::MAX),
        "Fix: adaptive_dense_step buffer size {} exceeds u32::MAX ({} nodes × {} words). \
         Partition the graph or use csr_forward_traverse.",
        adj_count,
        node_count,
        words,
    );
    let adj_count_u32 = adj_count as u32;
    let d = Expr::InvocationId { axis: 0 };

    let body: Vec<Node> = vec![
        Node::let_bind("row_start", Expr::mul(d.clone(), Expr::u32(words))),
        Node::let_bind("hit", Expr::u32(0)),
        Node::loop_for(
            "w",
            Expr::u32(0),
            Expr::u32(words),
            vec![Node::assign(
                "hit",
                Expr::bitor(
                    Expr::var("hit"),
                    Expr::bitand(
                        Expr::load(
                            adj_rows_dense,
                            Expr::add(Expr::var("row_start"), Expr::var("w")),
                        ),
                        Expr::load(frontier_in, Expr::var("w")),
                    ),
                ),
            )],
        ),
        Node::if_then(
            Expr::ne(Expr::var("hit"), Expr::u32(0)),
            vec![
                Node::let_bind("word_idx", Expr::shr(d.clone(), Expr::u32(5))),
                Node::let_bind(
                    "bit_mask",
                    Expr::shl(Expr::u32(1), Expr::bitand(d.clone(), Expr::u32(31))),
                ),
                Node::let_bind(
                    "_",
                    Expr::atomic_or(frontier_out, Expr::var("word_idx"), Expr::var("bit_mask")),
                ),
            ],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(frontier_in, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(words),
            BufferDecl::storage(frontier_out, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(words),
            BufferDecl::storage(adj_rows_dense, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(adj_count_u32),
        ],
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::lt(d.clone(), Expr::u32(node_count)),
                body,
            )]),
        }],
    )
}

/// CPU reference for the dense step. `frontier_in` is a packed
/// bitset over `node_count` nodes; `adj_rows_dense` is the reverse
/// adjacency laid out as `node_count × bitset_words(node_count)`.
#[must_use]
pub fn cpu_dense_step(frontier_in: &[u32], adj_rows_dense: &[u32], node_count: u32) -> Vec<u32> {
    let words = bitset_words(node_count) as usize;
    assert_eq!(frontier_in.len(), words);
    assert_eq!(adj_rows_dense.len(), (node_count as usize) * words);

    let mut out = vec![0_u32; words];
    for d in 0..node_count as usize {
        let row_start = d * words;
        let mut hit: u32 = 0;
        for w in 0..words {
            hit |= adj_rows_dense[row_start + w] & frontier_in[w];
        }
        if hit != 0 {
            out[d / 32] |= 1 << (d % 32);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack_nodes(bits: &[u32], node_count: u32) -> Vec<u32> {
        let mut buf = vec![0_u32; bitset_words(node_count) as usize];
        for &b in bits {
            buf[(b as usize) / 32] |= 1 << (b % 32);
        }
        buf
    }

    fn build_dense_adj(edges: &[(u32, u32)], node_count: u32) -> Vec<u32> {
        let words = bitset_words(node_count) as usize;
        let mut rows = vec![0_u32; (node_count as usize) * words];
        for &(src, dst) in edges {
            let idx = (dst as usize) * words + (src as usize) / 32;
            rows[idx] |= 1 << (src % 32);
        }
        rows
    }

    #[test]
    fn should_use_dense_empty_frontier_is_false() {
        assert!(!should_use_dense(&[0_u32], 32));
    }

    #[test]
    fn should_use_dense_zero_nodes_returns_false() {
        assert!(!should_use_dense(&[], 0));
    }

    #[test]
    fn should_use_dense_full_frontier_is_true() {
        let f = vec![0xFFFF_FFFF_u32; 4];
        assert!(should_use_dense(&f, 128));
    }

    #[test]
    fn should_use_dense_quarter_frontier_at_threshold() {
        // 32 nodes, 8 bits set = 25% (exactly threshold).
        assert!(should_use_dense(&[0xFF_u32], 32));
    }

    #[test]
    fn should_use_dense_just_under_threshold_is_false() {
        // 32 nodes, 7 bits set = ~21%, below 25%.
        assert!(!should_use_dense(&[0x7F_u32], 32));
    }

    #[test]
    fn cpu_dense_step_empty_frontier_produces_empty() {
        let frontier_in = pack_nodes(&[], 16);
        let adj = build_dense_adj(&[(0, 1), (1, 2)], 16);
        let out = cpu_dense_step(&frontier_in, &adj, 16);
        assert_eq!(out, vec![0; bitset_words(16) as usize]);
    }

    #[test]
    fn cpu_dense_step_single_edge() {
        let out = cpu_dense_step(&pack_nodes(&[0], 16), &build_dense_adj(&[(0, 1)], 16), 16);
        assert_eq!(out, pack_nodes(&[1], 16));
    }

    #[test]
    fn cpu_dense_step_fanout() {
        let out = cpu_dense_step(
            &pack_nodes(&[0], 16),
            &build_dense_adj(&[(0, 1), (0, 2), (0, 5)], 16),
            16,
        );
        assert_eq!(out, pack_nodes(&[1, 2, 5], 16));
    }

    #[test]
    fn cpu_dense_step_fanin() {
        let out = cpu_dense_step(
            &pack_nodes(&[1, 2], 16),
            &build_dense_adj(&[(1, 3), (2, 3), (4, 3)], 16),
            16,
        );
        assert_eq!(out, pack_nodes(&[3], 16));
    }

    #[test]
    fn cpu_dense_step_cross_word_boundary() {
        // 70 nodes → 3 words. Edge src=5 (word 0) → dst=65 (word 2).
        let out = cpu_dense_step(&pack_nodes(&[5], 70), &build_dense_adj(&[(5, 65)], 70), 70);
        assert_eq!(out, pack_nodes(&[65], 70));
    }

    #[test]
    fn cpu_dense_step_is_one_hop_only() {
        // Single invocation is one hop. 0 → 1 → 2 → 3; seeded with
        // {0} yields {1}, not the full closure.
        let out = cpu_dense_step(
            &pack_nodes(&[0], 16),
            &build_dense_adj(&[(0, 1), (1, 2), (2, 3)], 16),
            16,
        );
        assert_eq!(out, pack_nodes(&[1], 16));
    }

    #[test]
    fn emitted_program_has_expected_shape() {
        let p = adaptive_dense_step("fin", "fout", "adj", 64);
        assert_eq!(p.workgroup_size, [1, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["fin", "fout", "adj"]);
        let find = |name: &str| p.buffers.iter().find(|b| b.name() == name).unwrap().count;
        let words = bitset_words(64);
        assert_eq!(find("fin"), words);
        assert_eq!(find("fout"), words);
        assert_eq!(find("adj"), 64 * words);
    }

    #[test]
    fn selector_roundtrip_common_density_profiles() {
        // Sparse (1% density) → CSR.
        assert!(!should_use_dense(&pack_nodes(&[5], 512), 512));

        // Dense (50% density) → dense.
        let mut f = vec![0_u32; bitset_words(512) as usize];
        for b in 0..256_u32 {
            f[b as usize / 32] |= 1 << (b % 32);
        }
        assert!(should_use_dense(&f, 512));
    }
}
