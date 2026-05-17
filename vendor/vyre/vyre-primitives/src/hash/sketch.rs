//! Sketch primitives — Count-Sketch (Charikar 2002) and a leverage-
//! score (Drineas 2012) one-shot sampler.
//!
//! Sketches give compressed estimators for matrix products, norms,
//! eigenvalues, and frequency moments with provable error bounds.
//! Underexploited as a tier-2.5 primitive because deep learning ate
//! the attention budget — but the substrate is GPU-trivial.
//!
//! # Why this primitive is dual-use
//!
//! | Consumer | Use |
//! |---|---|
//! | `vyre-libs::streaming` consumers | streaming statistics with bounded memory |
//! | `vyre-libs::ml::sketch_lr` consumers | sketch-based linear regression / SVD |
//! | `vyre-libs::observability::histogram` consumers | approximate quantiles |
//! | `vyre-driver` profiling consumers | per-Program latency distribution in O(log n) memory — same primitive that user streaming dialects compose |
//!
//! # Operations
//!
//! - [`crate::hash::sketch::count_sketch_update`] — given an item and its hash + sign,
//!   add to the sketch table. Single-lane stream model.
//! - [`crate::hash::sketch::count_sketch_query_cpu`] — estimate frequency of an item by
//!   reading hash·sign-indexed cells across `d` independent sketches
//!   and taking the median of `sign * cell` reads.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Op id for the update primitive.
pub const UPDATE_OP_ID: &str = "vyre-primitives::hash::count_sketch_update";

/// Apply one item to the count-sketch table.
///
/// Inputs:
/// - `table`: `d * w` u32 cells (d sketches × w columns).
/// - `hashes`: `d` precomputed column indices in `[0, w)` for the
///   current item (one per sketch row).
/// - `signs`: `d` precomputed `±1` signs (encoded as `1` and
///   `0xFFFF_FFFF` in u32 two's-complement).
///
/// For each row r in 0..d:
///   `table[r*w + hashes[r]] += signs[r]`
///
/// Invalid dimensions lower to an explicit trap program.
#[must_use]
pub fn count_sketch_update(table: &str, hashes: &str, signs: &str, d: u32, w: u32) -> Program {
    if d == 0 {
        return crate::invalid_output_program(
            UPDATE_OP_ID,
            table,
            DataType::U32,
            format!("Fix: count_sketch_update requires d > 0, got {d}."),
        );
    }
    if w == 0 {
        return crate::invalid_output_program(
            UPDATE_OP_ID,
            table,
            DataType::U32,
            format!("Fix: count_sketch_update requires w > 0, got {w}."),
        );
    }

    let t = Expr::InvocationId { axis: 0 };
    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(d)),
        vec![
            Node::let_bind("col", Expr::load(hashes, t.clone())),
            Node::let_bind("sgn", Expr::load(signs, t.clone())),
            Node::let_bind("row_base", Expr::mul(t.clone(), Expr::u32(w))),
            Node::let_bind("addr", Expr::add(Expr::var("row_base"), Expr::var("col"))),
            Node::store(
                table,
                Expr::var("addr"),
                Expr::add(Expr::load(table, Expr::var("addr")), Expr::var("sgn")),
            ),
        ],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(table, 0, BufferAccess::ReadWrite, DataType::U32).with_count(d * w),
            BufferDecl::storage(hashes, 1, BufferAccess::ReadOnly, DataType::U32).with_count(d),
            BufferDecl::storage(signs, 2, BufferAccess::ReadOnly, DataType::U32).with_count(d),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(UPDATE_OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

// ---- CPU references ----

/// CPU helper: apply `(hashes, signs)` for one item to a (d × w) sketch.
/// Encoding: `signs[i]` is `+1` or `-1` as `i32`; we cast through `u32`
/// for the table representation.
pub fn count_sketch_update_cpu(table: &mut [u32], hashes: &[u32], signs: &[i32], d: u32, w: u32) {
    if w == 0
        || table.len() != d.saturating_mul(w) as usize
        || hashes.len() < d as usize
        || signs.len() < d as usize
    {
        return;
    }
    for r in 0..d as usize {
        let col = hashes[r] as usize;
        if col >= w as usize {
            continue;
        }
        let addr = r * w as usize + col;
        // Two's-complement add via u32 wrap is the GPU semantics.
        let cell = table[addr] as i32;
        table[addr] = (cell + signs[r]) as u32;
    }
}

/// CPU helper: estimate item frequency from sketch (median of
/// `sign[r] * table[r * w + hash[r]]` across the d rows).
#[must_use]
pub fn count_sketch_query_cpu(table: &[u32], hashes: &[u32], signs: &[i32], d: u32, w: u32) -> i32 {
    let mut estimates = Vec::new();
    count_sketch_query_cpu_into(table, hashes, signs, d, w, &mut estimates)
}

/// Caller-owned variant of [`count_sketch_query_cpu`].
pub fn count_sketch_query_cpu_into(
    table: &[u32],
    hashes: &[u32],
    signs: &[i32],
    d: u32,
    w: u32,
    estimates: &mut Vec<i32>,
) -> i32 {
    estimates.clear();
    if d == 0
        || w == 0
        || table.len() != d.saturating_mul(w) as usize
        || hashes.len() < d as usize
        || signs.len() < d as usize
    {
        return 0;
    }
    estimates.reserve(d as usize);
    for r in 0..d as usize {
        let col = hashes[r] as usize;
        if col >= w as usize {
            return 0;
        }
        let cell = table[r * w as usize + col] as i32;
        estimates.push(cell * signs[r]);
    }
    estimates.sort_unstable();
    estimates[estimates.len() / 2]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_single_item_round_trip() {
        // Insert item once, query — should return ~1.
        let d = 5u32;
        let w = 16u32;
        let mut table = vec![0u32; (d * w) as usize];
        let hashes = vec![3u32, 11, 2, 7, 14];
        let signs = vec![1i32, -1, 1, -1, 1];
        count_sketch_update_cpu(&mut table, &hashes, &signs, d, w);
        let est = count_sketch_query_cpu(&table, &hashes, &signs, d, w);
        assert_eq!(est, 1);
    }

    #[test]
    fn cpu_repeated_inserts_count() {
        let d = 5u32;
        let w = 16u32;
        let mut table = vec![0u32; (d * w) as usize];
        let hashes = vec![3u32, 11, 2, 7, 14];
        let signs = vec![1i32, -1, 1, -1, 1];
        for _ in 0..7 {
            count_sketch_update_cpu(&mut table, &hashes, &signs, d, w);
        }
        let est = count_sketch_query_cpu(&table, &hashes, &signs, d, w);
        assert_eq!(est, 7);
    }

    #[test]
    fn cpu_unrelated_query_returns_zero_or_small() {
        // After inserting one item, a different item with disjoint
        // hashes should query as 0.
        let d = 5u32;
        let w = 16u32;
        let mut table = vec![0u32; (d * w) as usize];
        let h_a = vec![3u32, 11, 2, 7, 14];
        let s_a = vec![1i32, -1, 1, -1, 1];
        count_sketch_update_cpu(&mut table, &h_a, &s_a, d, w);

        let h_b = vec![5u32, 9, 0, 4, 12];
        let s_b = vec![-1i32, 1, -1, 1, -1];
        let est = count_sketch_query_cpu(&table, &h_b, &s_b, d, w);
        assert_eq!(est, 0);
    }

    #[test]
    fn cpu_two_items_independent_estimates() {
        let d = 7u32;
        let w = 32u32;
        let mut table = vec![0u32; (d * w) as usize];
        let h_a = vec![1u32, 2, 3, 4, 5, 6, 7];
        let s_a = vec![1i32, 1, -1, 1, -1, 1, 1];
        let h_b = vec![10u32, 20, 30, 11, 21, 0, 25];
        let s_b = vec![-1i32, 1, 1, -1, 1, 1, -1];

        for _ in 0..3 {
            count_sketch_update_cpu(&mut table, &h_a, &s_a, d, w);
        }
        for _ in 0..5 {
            count_sketch_update_cpu(&mut table, &h_b, &s_b, d, w);
        }
        assert_eq!(count_sketch_query_cpu(&table, &h_a, &s_a, d, w), 3);
        assert_eq!(count_sketch_query_cpu(&table, &h_b, &s_b, d, w), 5);
    }

    #[test]
    fn cpu_helpers_reject_malformed_inputs_without_panicking() {
        let mut table = vec![9u32; 4];
        count_sketch_update_cpu(&mut table, &[9], &[1], 2, 2);
        assert_eq!(table, vec![9u32; 4]);

        let mut estimates = Vec::with_capacity(8);
        let ptr = estimates.as_ptr();
        let got = count_sketch_query_cpu_into(&table, &[99, 1], &[1, 1], 2, 2, &mut estimates);
        assert_eq!(got, 0);
        assert_eq!(estimates.as_ptr(), ptr);
    }

    #[test]
    fn ir_program_buffer_layout() {
        let p = count_sketch_update("t", "h", "s", 5, 16);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["t", "h", "s"]);
        assert_eq!(p.buffers[0].count(), 5 * 16);
        assert_eq!(p.buffers[1].count(), 5);
        assert_eq!(p.buffers[2].count(), 5);
    }

    #[test]
    fn zero_d_traps() {
        let p = count_sketch_update("t", "h", "s", 0, 16);
        assert!(p.stats().trap());
    }

    #[test]
    fn zero_w_traps() {
        let p = count_sketch_update("t", "h", "s", 5, 0);
        assert!(p.stats().trap());
    }
}
