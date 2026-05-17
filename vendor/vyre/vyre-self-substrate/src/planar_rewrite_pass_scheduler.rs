//! IR rewrite-batch scheduler via #11 planar_rewrite (#11 self-consumer).
//!
//! Closes the recursion thesis for #11 — planar grammar rewriting
//! ships to user dialects (visual-programming languages, 2D
//! pattern-matching languages) AND schedules vyre's own batch IR
//! rewrites for non-conflicting parallel application.
//!
//! # The self-use
//!
//! Vyre's optimizer applies many local rewrites per pass — fold a
//! constant, inline a region, eliminate a dead store. When N
//! candidate rewrites apply to the same Region, naive sequential
//! application means N kernel launches and N validation steps.
//!
//! Most of those N rewrites operate on disjoint sub-trees of the
//! Region tree. They could batch into ONE parallel application —
//! the only constraint is "two rewrites can't touch overlapping
//! sub-trees in the same batch."
//!
//! That's exactly the **planar non-overlapping selection** problem
//! that `planar_rewrite_schedule` solves: given a 2D grid of
//! candidate matches, greedily select a maximum non-overlapping
//! subset.
//!
//! # Algorithm
//!
//! ```text
//! 1. lay out the Region tree as a 2D grid (rows = depth, columns =
//!    sibling order)
//! 2. mark `candidates[i, j] = 1` for every (i, j) where a rewrite
//!    pattern matches
//! 3. planar_rewrite_schedule_cpu(candidates, h, w, k=2) — k=2 means
//!    each rewrite "covers" a 2×2 sub-region (parent + immediate
//!    descendant). Returns the maximum non-conflicting subset.
//! 4. apply the selected rewrites in ONE batched dispatch
//! ```
//!
//! # Why this matters
//!
//! At workspace scale, an optimizer pass may have 100k+ candidate
//! rewrites. Sequential application with kernel launch overhead
//! kills throughput. Planar-scheduled batching cuts the dispatch
//! count by orders of magnitude with provably-correct disjointness
//! (the greedy schedule never picks two overlapping rewrites).

use vyre_primitives::parsing::planar_rewrite::planar_rewrite_schedule_cpu;

/// Schedule a batch of non-conflicting IR rewrites. `candidates` is
/// a `h × w` row-major 0/1 grid where 1 marks a rewrite-pattern
/// match. `k` is the rewrite footprint (each selected rewrite
/// "covers" a k × k sub-region).
///
/// Returns a 0/1 grid where 1 marks a rewrite to apply in this
/// batch. Selected rewrites are disjoint by construction.
///
/// # Panics
///
/// Panics if `candidates.len() != h*w` or `k == 0`.
#[must_use]
pub fn schedule_disjoint_rewrites(candidates: &[u32], h: u32, w: u32, k: u32) -> Vec<u32> {
    use crate::observability::{bump, planar_rewrite_pass_scheduler_calls};
    bump(&planar_rewrite_pass_scheduler_calls);
    assert!(k > 0, "Fix: rewrite footprint k must be > 0.");
    planar_rewrite_schedule_cpu(candidates, h, w, k)
}

/// Convenience: count how many rewrites the schedule selected.
#[must_use]
pub fn count_scheduled(schedule: &[u32]) -> u32 {
    schedule.iter().filter(|&&v| v != 0).count() as u32
}

/// Convenience: estimate batch reduction. Returns the speedup
/// ratio (candidates / scheduled) — a 100× speedup means the
/// scheduler picked 1% of candidates per batch (others apply in
/// later batches).
#[must_use]
pub fn batch_reduction_ratio(candidate_count: u32, scheduled_count: u32) -> f64 {
    if scheduled_count == 0 {
        return 0.0;
    }
    candidate_count as f64 / scheduled_count as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_grid_yields_no_schedule() {
        let candidates = vec![0u32; 16];
        let schedule = schedule_disjoint_rewrites(&candidates, 4, 4, 2);
        assert_eq!(count_scheduled(&schedule), 0);
    }

    #[test]
    fn full_grid_yields_disjoint_subset() {
        // 4x4 grid, all candidates, k=2. Expected: at most ⌈4/2⌉² = 4
        // rewrites picked at positions (0,0), (0,2), (2,0), (2,2).
        let candidates = vec![1u32; 16];
        let schedule = schedule_disjoint_rewrites(&candidates, 4, 4, 2);
        let count = count_scheduled(&schedule);
        // Disjointness with k=2 footprint allows at most 4 rewrites.
        assert!(count >= 1, "at least one rewrite must be schedulable");
        assert!(count <= 4, "at most 4 disjoint k=2 rewrites in a 4x4 grid");
    }

    #[test]
    fn batch_reduction_well_defined() {
        assert_eq!(batch_reduction_ratio(0, 0), 0.0);
        let r = batch_reduction_ratio(100, 4);
        assert!((r - 25.0).abs() < 1e-9);
    }

    #[test]
    fn k_one_allows_every_candidate() {
        // k=1 means each rewrite covers a 1x1 sub-region — no
        // overlap possible, so every candidate is selectable.
        let candidates = vec![1u32, 1, 1, 1];
        let schedule = schedule_disjoint_rewrites(&candidates, 2, 2, 1);
        assert_eq!(count_scheduled(&schedule), 4);
    }
}
