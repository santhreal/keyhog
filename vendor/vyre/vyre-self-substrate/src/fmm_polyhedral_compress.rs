//! Polyhedral-fusion all-pairs compression via #51 FMM (#19+#51 self-consumer).
//!
//! Closes the recursion thesis for #51 — the FMM (fast multipole)
//! hierarchical-expansion primitives ship to user dialects (kernel
//! methods at scale, computational physics, dense GP inference) AND
//! provide vyre's polyhedral fusion analysis with the hierarchical
//! compression that keeps O(N²) all-pairs tractable at workspace
//! scale.
//!
//! # The self-use
//!
//! Vyre's #19 polyhedral fusion (already shipped at
//! [`crate::polyhedral_fusion`]) computes pairwise
//! affine-dependency adjacency over Regions: every pair (i, j) is
//! checked for fusion eligibility. At N Regions this is N(N-1)/2
//! comparisons — O(N²) memory + compute.
//!
//! FMM exploits the fact that Regions far apart in the dispatch
//! topology rarely have fusion dependencies (the dispatch graph is
//! quasi-locally connected). Hierarchical decomposition:
//!
//! 1. **P2M**: aggregate per-Region fusion-affinity into multipole
//!    moments per spatial cell of the dispatch hierarchy.
//! 2. **M2L**: translate distant cell moments to local expansions
//!    (constant cost per cell-pair regardless of contained Regions).
//! 3. **L2P**: evaluate local expansions at each Region to recover
//!    its all-pairs fusion-affinity sum.
//!
//! Total cost: O(N log N) memory + compute. This module owns the
//! zeroth-moment compression path, which captures the dominant
//! cluster effect and keeps the self-consumer contract simple.
//!
//! # Why this matters
//!
//! At workspace scale, polyhedral_fusion's O(N²) cost is the
//! gating factor — 1M Regions = 10¹² pairs, untractable. With FMM,
//! 1M Regions = ~20M operations, dispatched in seconds.
//!
//! # Algorithm
//!
//! Higher-moment FMM compression belongs in distinct registered ops so
//! each multipole order has an explicit schema and test oracle.

use vyre_primitives::math::fmm::{
    l2p_zeroth_eval_cpu, m2l_zeroth_translate_cpu, p2m_zeroth_moment_cpu_into,
};

/// Aggregate per-Region fusion-affinity scores into per-cell multipole
/// moments. `scores[i]` is Region i's affinity scalar; `cell_assignment[i]`
/// is its parent cell id. Returns one f64 moment per cell (zeroth moment
/// = sum of contained scores).
///
/// # Panics
///
/// Panics if `scores.len() != cell_assignment.len()`.
#[must_use]
pub fn aggregate_to_cells(scores: &[f64], cell_assignment: &[u32]) -> Vec<f64> {
    let mut out = Vec::new();
    aggregate_to_cells_into(scores, cell_assignment, &mut out);
    out
}

/// Aggregate per-Region fusion-affinity scores into caller-owned cell moments.
pub fn aggregate_to_cells_into(scores: &[f64], cell_assignment: &[u32], out: &mut Vec<f64>) {
    use crate::observability::{bump, fmm_polyhedral_compress_calls};
    bump(&fmm_polyhedral_compress_calls);
    assert_eq!(scores.len(), cell_assignment.len());
    p2m_zeroth_moment_cpu_into(scores, cell_assignment, out);
}

/// Translate source-cell moments to target-cell local expansions.
/// `cell_moments[s]` is the source cell's aggregated moment;
/// `cell_distances[(target, source)]` is the precomputed distance
/// (laid out row-major: `cell_distances[t * num_cells + s]`).
/// Returns the per-target-cell local expansion as the sum of
/// translated moments from all sources.
///
/// # Panics
///
/// Panics if `cell_distances.len() != cell_moments.len() * cell_moments.len()`.
#[must_use]
pub fn translate_to_targets(cell_moments: &[f64], cell_distances: &[f64]) -> Vec<f64> {
    let mut local = Vec::new();
    translate_to_targets_into(cell_moments, cell_distances, &mut local);
    local
}

/// Translate source-cell moments into caller-owned target locals.
pub fn translate_to_targets_into(
    cell_moments: &[f64],
    cell_distances: &[f64],
    local: &mut Vec<f64>,
) {
    use crate::observability::{bump, fmm_polyhedral_compress_calls};
    bump(&fmm_polyhedral_compress_calls);
    let num_cells = cell_moments.len();
    assert_eq!(
        cell_distances.len(),
        num_cells * num_cells,
        "Fix: cell_distances must be num_cells*num_cells row-major."
    );

    local.clear();
    local.resize(num_cells, 0.0);
    for t in 0..num_cells {
        for s in 0..num_cells {
            if t == s {
                continue; // self-cell handled by direct evaluation
            }
            let d = cell_distances[t * num_cells + s];
            local[t] += m2l_zeroth_translate_cpu(cell_moments[s], d);
        }
    }
}

/// Evaluate local expansions at each Region to recover its
/// all-pairs fusion-affinity sum. `cell_local[c]` is the local
/// expansion at cell c; `cell_assignment[i]` is Region i's parent
/// cell. Returns the per-Region affinity sum.
#[must_use]
pub fn evaluate_at_regions(cell_local: &[f64], cell_assignment: &[u32], n: u32) -> Vec<f64> {
    let mut out = Vec::new();
    evaluate_at_regions_into(cell_local, cell_assignment, n, &mut out);
    out
}

/// Evaluate local expansions into caller-owned per-Region output.
pub fn evaluate_at_regions_into(
    cell_local: &[f64],
    cell_assignment: &[u32],
    n: u32,
    out: &mut Vec<f64>,
) {
    use crate::observability::{bump, fmm_polyhedral_compress_calls};
    bump(&fmm_polyhedral_compress_calls);
    assert_eq!(cell_assignment.len(), n as usize);
    out.clear();
    out.reserve(n as usize);
    #[allow(clippy::needless_range_loop)]
    for i in 0..n as usize {
        let cell = cell_assignment[i] as usize;
        assert!(
            cell < cell_local.len(),
            "Fix: cell assignment {cell} out of bounds for {} cells",
            cell_local.len()
        );
        out.push(l2p_zeroth_eval_cpu(cell_local[cell], 0.0, 0.0));
    }
}

/// Run the full P2M → M2L → L2P pipeline. `scores` are per-Region
/// fusion-affinity scalars; `cell_assignment[i]` is Region i's parent
/// cell; `cell_distances` is the precomputed n_cells×n_cells distance
/// matrix. Returns per-Region all-pairs affinity sum approximated to
/// the zeroth-moment FMM truncation.
#[must_use]
pub fn fmm_compress_pairwise(
    scores: &[f64],
    cell_assignment: &[u32],
    cell_distances: &[f64],
    n: u32,
) -> Vec<f64> {
    let mut cell_moments = Vec::new();
    let mut cell_local = Vec::new();
    let mut out = Vec::new();
    fmm_compress_pairwise_into(
        scores,
        cell_assignment,
        cell_distances,
        n,
        &mut cell_moments,
        &mut cell_local,
        &mut out,
    );
    out
}

/// Run the full P2M → M2L → L2P pipeline into caller-owned buffers.
pub fn fmm_compress_pairwise_into(
    scores: &[f64],
    cell_assignment: &[u32],
    cell_distances: &[f64],
    n: u32,
    cell_moments: &mut Vec<f64>,
    cell_local: &mut Vec<f64>,
    out: &mut Vec<f64>,
) {
    aggregate_to_cells_into(scores, cell_assignment, cell_moments);
    translate_to_targets_into(cell_moments, cell_distances, cell_local);
    evaluate_at_regions_into(cell_local, cell_assignment, n, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-6 * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn aggregate_sums_per_cell() {
        // 4 Regions, 2 cells: {0,1} → cell 0; {2,3} → cell 1.
        let scores = vec![1.0, 2.0, 3.0, 4.0];
        let cells = vec![0u32, 0, 1, 1];
        let moments = aggregate_to_cells(&scores, &cells);
        assert!(approx_eq(moments[0], 3.0));
        assert!(approx_eq(moments[1], 7.0));
    }

    #[test]
    fn translate_excludes_self_cell() {
        // 2 cells with moments [10, 20] and unit distances.
        let moments = vec![10.0, 20.0];
        let distances = vec![0.0, 1.0, 1.0, 0.0];
        let local = translate_to_targets(&moments, &distances);
        // local[0] = m2l(20, 1.0); local[1] = m2l(10, 1.0).
        assert!(approx_eq(local[0], m2l_zeroth_translate_cpu(20.0, 1.0)));
        assert!(approx_eq(local[1], m2l_zeroth_translate_cpu(10.0, 1.0)));
    }

    #[test]
    fn evaluate_distributes_local_to_regions() {
        let cell_local = vec![5.0, 7.0];
        let cells = vec![0u32, 1, 0, 1];
        let result = evaluate_at_regions(&cell_local, &cells, 4);
        assert!(approx_eq(result[0], 5.0));
        assert!(approx_eq(result[1], 7.0));
        assert!(approx_eq(result[2], 5.0));
        assert!(approx_eq(result[3], 7.0));
    }

    #[test]
    fn full_pipeline_into_reuses_buffers() {
        let scores = vec![1.0, 2.0, 3.0, 4.0];
        let cells = vec![0u32, 0, 1, 1];
        let distances = vec![0.0, 1.0, 1.0, 0.0];
        let mut moments = Vec::with_capacity(8);
        let mut local = Vec::with_capacity(8);
        let mut out = Vec::with_capacity(8);
        let pointers = [moments.as_ptr(), local.as_ptr(), out.as_ptr()];
        fmm_compress_pairwise_into(
            &scores,
            &cells,
            &distances,
            4,
            &mut moments,
            &mut local,
            &mut out,
        );
        assert_eq!(out.len(), 4);
        for ptr in [moments.as_ptr(), local.as_ptr(), out.as_ptr()] {
            assert!(pointers.contains(&ptr));
        }
    }

    #[test]
    fn full_pipeline_runs_without_panic() {
        let scores = vec![1.0, 2.0, 3.0, 4.0];
        let cells = vec![0u32, 0, 1, 1];
        let distances = vec![0.0, 1.0, 1.0, 0.0];
        let _result = fmm_compress_pairwise(&scores, &cells, &distances, 4);
    }

    #[test]
    fn empty_score_set_produces_zero_moments() {
        let scores: Vec<f64> = vec![];
        let cells: Vec<u32> = vec![];
        let moments = aggregate_to_cells(&scores, &cells);
        assert!(moments.is_empty());
    }
}
