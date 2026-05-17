//! Region-tree coarse-graining via #58 Mori-Zwanzig projection (#58 self-consumer).
//!
//! Closes the recursion thesis for #58 — `mz_project_step` ships to
//! user dialects (climate modeling, scientific ML model reduction)
//! AND derives vyre's coarse-grained dispatch view of its own Region
//! tree.
//!
//! # The self-use
//!
//! Vyre's full dispatch graph at workspace scale is millions of
//! Regions. Most optimizer passes don't need that resolution — they
//! need a coarse view that preserves the dispatch structure (memory
//! pressure, sync points, fusion eligibility) while dropping leaf
//! detail. Mori-Zwanzig (1965) gives an EXACT reduction with a
//! memory kernel that captures whatever the projection drops.
//!
//! Concretely: cluster Regions into K macro-nodes via #2 sinkhorn
//! divergence (the substrate clustering primitive #31 ships).
//! Construct a projection matrix P that averages within each cluster.
//! Mori-Zwanzig's projection step yields the coarse dispatch
//! dynamics; the memory kernel encodes how within-cluster detail
//! influences cross-cluster decisions over time (= over subsequent
//! optimizer passes).
//!
//! This module owns the coarse-graining projection step. Memory-kernel
//! recursion composes with this projection when a pass framework
//! supplies historical state.
//!
//! # Algorithm
//!
//! ```text
//! P[i,j] = 1/|cluster(i)|  if cluster(i) == cluster(j) else 0
//! coarse_state = P · state  (one mz_project_step dispatch)
//! ```
//!
//! `state[i]` is any per-Region scalar feature (memory residency,
//! dispatch latency, fusion-eligibility score). The projected
//! `coarse_state[i]` is the cluster-averaged value at i.
//!
//! # Why this matters at scale
//!
//! At 1M Regions, naive full-resolution analysis is O(N²) memory in
//! the worst case (#19 polyhedral fusion considers all pairs).
//! Mori-Zwanzig coarsening to K macro-nodes drops that to O(K²) at
//! the cost of an exactly-quantified projection error — the memory
//! kernel. Combined with #51 FMM hierarchical compression on the
//! coarse system, full workspace analysis stays tractable.

use vyre_primitives::math::mori_zwanzig::mz_project_step_cpu_into;

/// Reusable buffers for Mori-Zwanzig region coarsening.
#[derive(Debug, Default)]
pub struct RegionCoarsenScratch {
    cluster_sizes: Vec<u32>,
    projection: Vec<f64>,
    coarse_state: Vec<f64>,
}

impl RegionCoarsenScratch {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn projection_ptr(&self) -> *const f64 {
        self.projection.as_ptr()
    }
}

/// Build a cluster-projection matrix from a cluster-assignment
/// vector. `assignments[i]` is the cluster id (0..k) of Region i.
/// Returns a row-major n*n matrix where row i is uniform over its
/// cluster's column indices.
///
/// # Panics
///
/// Panics if any assignment exceeds k-1.
#[must_use]
pub fn cluster_projection_matrix(assignments: &[u32], n: u32, k: u32) -> Vec<f64> {
    let mut scratch = RegionCoarsenScratch::new();
    cluster_projection_matrix_into(assignments, n, k, &mut scratch).to_vec()
}

/// Build a cluster-projection matrix using caller-owned scratch.
#[must_use]
pub fn cluster_projection_matrix_into<'a>(
    assignments: &[u32],
    n: u32,
    k: u32,
    scratch: &'a mut RegionCoarsenScratch,
) -> &'a [f64] {
    use crate::observability::{bump, mori_zwanzig_region_coarsen_calls};
    bump(&mori_zwanzig_region_coarsen_calls);
    assert!(n > 0);
    assert!(k > 0);
    assert_eq!(assignments.len(), n as usize);
    let n = n as usize;
    let k = k as usize;

    scratch.cluster_sizes.clear();
    scratch.cluster_sizes.resize(k, 0);
    for &c in assignments {
        assert!(
            (c as usize) < k,
            "Fix: assignment {c} exceeds cluster count {k}."
        );
        scratch.cluster_sizes[c as usize] += 1;
    }

    scratch.projection.clear();
    scratch.projection.resize(n * n, 0.0);
    for i in 0..n {
        let ci = assignments[i] as usize;
        let size = scratch.cluster_sizes[ci] as f64;
        if size == 0.0 {
            continue;
        }
        let inv = 1.0 / size;
        #[allow(clippy::needless_range_loop)]
        for j in 0..n {
            if assignments[j] as usize == ci {
                scratch.projection[i * n + j] = inv;
            }
        }
    }
    &scratch.projection
}

/// Apply Mori-Zwanzig projection to coarse-grain a per-Region scalar
/// feature vector. Returns the coarse-grained state where each
/// Region's value is replaced by its cluster-mean.
///
/// # Panics
///
/// Panics if `state.len() != n`.
#[must_use]
pub fn coarsen_region_state(p_matrix: &[f64], state: &[f64], n: u32) -> Vec<f64> {
    let mut out = Vec::new();
    coarsen_region_state_into(p_matrix, state, n, &mut out);
    out
}

/// Apply Mori-Zwanzig projection using caller-owned output storage.
pub fn coarsen_region_state_into(p_matrix: &[f64], state: &[f64], n: u32, out: &mut Vec<f64>) {
    use crate::observability::{bump, mori_zwanzig_region_coarsen_calls};
    bump(&mori_zwanzig_region_coarsen_calls);
    mz_project_step_cpu_into(p_matrix, state, n, out);
}

/// Convenience: derive the projection AND apply it in one step.
#[must_use]
pub fn coarsen_via_clustering(state: &[f64], assignments: &[u32], n: u32, k: u32) -> Vec<f64> {
    let mut scratch = RegionCoarsenScratch::new();
    coarsen_via_clustering_into(state, assignments, n, k, &mut scratch).to_vec()
}

/// Derive and apply the projection using caller-owned scratch.
#[must_use]
pub fn coarsen_via_clustering_into<'a>(
    state: &[f64],
    assignments: &[u32],
    n: u32,
    k: u32,
    scratch: &'a mut RegionCoarsenScratch,
) -> &'a [f64] {
    let projection_len = cluster_projection_matrix_into(assignments, n, k, scratch).len();
    debug_assert_eq!(
        projection_len,
        (n as usize).saturating_mul(k as usize),
        "cluster projection matrix must be n*k"
    );
    let RegionCoarsenScratch {
        projection,
        coarse_state,
        ..
    } = scratch;
    mz_project_step_cpu_into(projection, state, n, coarse_state);
    coarse_state
}

#[cfg(test)]
mod tests {
    #![allow(clippy::identity_op, clippy::erasing_op)]
    use super::*;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn projection_matrix_normalizes_within_cluster() {
        // 4 nodes, 2 clusters: {0,1} and {2,3}.
        let assignments = vec![0u32, 0, 1, 1];
        let p = cluster_projection_matrix(&assignments, 4, 2);
        // Row 0: uniform over cols 0+1, zero on 2+3.
        assert!(approx_eq(p[0], 0.5));
        assert!(approx_eq(p[1], 0.5));
        assert!(approx_eq(p[2], 0.0));
        assert!(approx_eq(p[3], 0.0));
        // Row 2: uniform over cols 2+3.
        assert!(approx_eq(p[2 * 4 + 2], 0.5));
        assert!(approx_eq(p[2 * 4 + 3], 0.5));
        assert!(approx_eq(p[2 * 4 + 0], 0.0));
    }

    #[test]
    fn coarsening_replaces_with_cluster_mean() {
        // 4 nodes, 2 clusters; state values [10, 20, 100, 200].
        // After coarsening: cluster 0 mean = 15, cluster 1 mean = 150.
        let assignments = vec![0u32, 0, 1, 1];
        let state = vec![10.0, 20.0, 100.0, 200.0];
        let coarse = coarsen_via_clustering(&state, &assignments, 4, 2);
        assert!(approx_eq(coarse[0], 15.0));
        assert!(approx_eq(coarse[1], 15.0));
        assert!(approx_eq(coarse[2], 150.0));
        assert!(approx_eq(coarse[3], 150.0));
    }

    #[test]
    fn singleton_clusters_preserve_state() {
        // Each Region is its own cluster — projection is identity.
        let assignments = vec![0u32, 1, 2, 3];
        let state = vec![10.0, 20.0, 30.0, 40.0];
        let coarse = coarsen_via_clustering(&state, &assignments, 4, 4);
        for (a, b) in state.iter().zip(coarse.iter()) {
            assert!(approx_eq(*a, *b));
        }
    }

    #[test]
    fn single_global_cluster_yields_uniform_mean() {
        // All Regions in one cluster — every coarse cell = global mean.
        let assignments = vec![0u32; 4];
        let state = vec![10.0, 20.0, 30.0, 40.0];
        let coarse = coarsen_via_clustering(&state, &assignments, 4, 1);
        let mean = (10.0 + 20.0 + 30.0 + 40.0) / 4.0;
        for v in coarse {
            assert!(approx_eq(v, mean));
        }
    }

    #[test]
    #[should_panic(expected = "exceeds cluster count")]
    fn rejects_out_of_range_assignment() {
        let assignments = vec![0u32, 1, 5, 0];
        cluster_projection_matrix(&assignments, 4, 2);
    }

    #[test]
    fn coarsen_via_clustering_into_reuses_projection_storage() {
        let assignments = vec![0u32, 0, 1, 1];
        let state = vec![10.0, 20.0, 100.0, 200.0];
        let mut scratch = RegionCoarsenScratch::new();

        let first = coarsen_via_clustering_into(&state, &assignments, 4, 2, &mut scratch).to_vec();
        let ptr = scratch.projection_ptr();
        let second = coarsen_via_clustering_into(&state, &assignments, 4, 2, &mut scratch).to_vec();

        assert!(approx_eq(first[0], 15.0));
        assert_eq!(first, second);
        assert_eq!(scratch.projection_ptr(), ptr);
    }
}
