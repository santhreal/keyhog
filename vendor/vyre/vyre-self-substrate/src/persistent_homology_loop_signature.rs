//! Region-tree loop topology via #15 vietoris_rips (#15 self-consumer).
//!
//! Closes the recursion thesis for #15 — vietoris_rips edge filtering
//! ships to user dialects (cosmology, biological networks, mesh
//! topology) AND extracts vyre's loop-nest topological signatures
//! for fusion-vs-fission scheduling.
//!
//! # The self-use
//!
//! Vyre's optimizer chooses between **loop fusion** (merge two
//! adjacent loops into one) and **loop fission** (split one loop
//! into two), driven by data-locality + register-pressure heuristics.
//! These heuristics are local — they don't see the full topology of
//! a loop nest. Persistent homology DOES see it: the H₁ persistence
//! diagram of the Region-tree filtration encodes how nested loops
//! merge as the "scale" parameter ε grows.
//!
//! H₁ persistent features (loops born early, die late) → big nested
//! loops worth fusing across.
//! H₁ transient features (loops born late, die early) → tight
//! locality-coherent loops worth fissioning.
//!
//! Vietoris-Rips edge filtering at scale ε is the first step of the
//! persistent homology computation — extract the 1-skeleton of the
//! filtration, then count cycles per ε.
//!
//! # Algorithm
//!
//! ```text
//! 1. compute pairwise Region-distance matrix d(i, j)
//!    (e.g. shared-buffer-set Jaccard distance)
//! 2. for each ε in [ε_min, ε_max]:
//!    - vietoris_rips_edge_filter(d, ε) → edge mask
//!    - count cycles in (V, edge_mask) → β₁(ε)
//! 3. persistent features = pairs (born, died) over the ε sequence
//! ```
//!
//! Per-ε cycle counting consumes
//! [`vyre_primitives::topology::betti_persistence::betti_persistence_cpu`]:
//! the 1-skeleton's union-find pass returns `(b0, b1, edges)` and lets
//! the optimizer track how many independent cycles persist as ε grows.
//!
//! # Why this matters
//!
//! Loop-nest topology is the substrate decision for ANY
//! cache-aware loop optimizer. Vyre is the first GPU substrate to
//! compute it via persistent homology.

use vyre_primitives::topology::vietoris_rips::extract_edges_cpu;

/// Reusable buffers for loop-topology filtration sweeps.
#[derive(Debug, Default)]
pub struct LoopTopologyScratch {
    mask: Vec<u32>,
    parent: Vec<u32>,
    rank: Vec<u32>,
}

/// Compute the Vietoris-Rips 1-skeleton at scale `epsilon` over the
/// Region-distance matrix. Returns the edge mask.
///
/// # Panics
///
/// Panics if `dist_matrix.len() != n*n`.
#[must_use]
pub fn region_loop_skeleton(dist_matrix: &[f64], epsilon: f64, n: u32) -> Vec<u32> {
    let mut out = Vec::new();
    region_loop_skeleton_into(dist_matrix, epsilon, n, &mut out);
    out
}

/// Compute the Vietoris-Rips 1-skeleton into caller-owned storage.
pub fn region_loop_skeleton_into(dist_matrix: &[f64], epsilon: f64, n: u32, out: &mut Vec<u32>) {
    use crate::observability::{bump, persistent_homology_loop_signature_calls};
    bump(&persistent_homology_loop_signature_calls);
    let n_us = n as usize;
    assert_eq!(dist_matrix.len(), n_us * n_us);
    out.clear();
    out.resize(n_us * n_us, 0);
    for i in 0..n_us {
        for j in (i + 1)..n_us {
            if dist_matrix[i * n_us + j] <= epsilon {
                out[i * n_us + j] = 1;
            }
        }
    }
}

/// Convenience: extract the edge list of the 1-skeleton.
#[must_use]
pub fn region_loop_edges(dist_matrix: &[f64], epsilon: f64, n: u32) -> Vec<(u32, u32)> {
    let mask = region_loop_skeleton(dist_matrix, epsilon, n);
    extract_edges_cpu(&mask, n)
}

/// Sweep over a range of ε scales and return the edge count at
/// each scale.
///
/// `epsilons` is a sorted-ascending sequence of scale parameters.
/// Returns one edge-count per ε.
#[must_use]
pub fn loop_filtration_edge_counts(dist_matrix: &[f64], epsilons: &[f64], n: u32) -> Vec<u32> {
    let mut scratch = LoopTopologyScratch::default();
    let mut out = Vec::with_capacity(epsilons.len());
    loop_filtration_edge_counts_into(dist_matrix, epsilons, n, &mut scratch, &mut out);
    out
}

/// Sweep over ε scales into caller-owned output.
pub fn loop_filtration_edge_counts_into(
    dist_matrix: &[f64],
    epsilons: &[f64],
    n: u32,
    scratch: &mut LoopTopologyScratch,
    out: &mut Vec<u32>,
) {
    out.clear();
    out.reserve(epsilons.len());
    for &eps in epsilons {
        region_loop_skeleton_into(dist_matrix, eps, n, &mut scratch.mask);
        out.push(scratch.mask.iter().filter(|&&v| v != 0).count() as u32);
    }
}

/// Sweep over `epsilons` and return `(b0, b1)` — connected components
/// and independent-cycle count — at each scale.
///
/// `b1` rises every time a new loop closes in the 1-skeleton; that
/// jump is exactly an H₁ persistent feature being born. The optimizer
/// uses these jumps to detect loop-nest topology that the local
/// fusion/fission heuristic doesn't see.
///
/// Composes [`region_loop_skeleton`] (Vietoris-Rips edge filter) with
/// `betti_persistence_cpu` (union-find cycle count).
#[must_use]
pub fn loop_filtration_betti(dist_matrix: &[f64], epsilons: &[f64], n: u32) -> Vec<(u32, u32)> {
    let mut scratch = LoopTopologyScratch::default();
    let mut out = Vec::with_capacity(epsilons.len());
    loop_filtration_betti_into(dist_matrix, epsilons, n, &mut scratch, &mut out);
    out
}

/// Sweep over ε scales and write `(b0, b1)` into caller-owned output.
pub fn loop_filtration_betti_into(
    dist_matrix: &[f64],
    epsilons: &[f64],
    n: u32,
    scratch: &mut LoopTopologyScratch,
    out: &mut Vec<(u32, u32)>,
) {
    out.clear();
    out.reserve(epsilons.len());
    for &eps in epsilons {
        region_loop_skeleton_into(dist_matrix, eps, n, &mut scratch.mask);
        let (b0, b1, _edges) =
            betti_persistence_into(&scratch.mask, n, &mut scratch.parent, &mut scratch.rank);
        out.push((b0, b1));
    }
}

/// Find every ε at which a new H₁ feature is born — i.e. an ε where
/// the cycle count `b1` strictly increases over the previous ε.
/// Returns the sequence of `(epsilon, b1_after)` pairs.
///
/// These are the loop-nest "scale signatures" the optimizer fuses on:
/// a small ε with sudden b1 jump = tightly coupled loops worth fusing;
/// a large ε with no b1 change = independent loops worth fissioning.
#[must_use]
pub fn h1_birth_scales(dist_matrix: &[f64], epsilons: &[f64], n: u32) -> Vec<(f64, u32)> {
    let mut scratch = LoopTopologyScratch::default();
    let mut births = Vec::new();
    h1_birth_scales_into(dist_matrix, epsilons, n, &mut scratch, &mut births);
    births
}

/// Find H1 birth scales into caller-owned output without materializing
/// the full Betti series.
pub fn h1_birth_scales_into(
    dist_matrix: &[f64],
    epsilons: &[f64],
    n: u32,
    scratch: &mut LoopTopologyScratch,
    births: &mut Vec<(f64, u32)>,
) {
    let mut prev_b1 = 0u32;
    births.clear();
    for &eps in epsilons {
        region_loop_skeleton_into(dist_matrix, eps, n, &mut scratch.mask);
        let (_b0, b1, _edges) =
            betti_persistence_into(&scratch.mask, n, &mut scratch.parent, &mut scratch.rank);
        if b1 > prev_b1 {
            births.push((eps, b1));
        }
        prev_b1 = b1;
    }
}

fn betti_persistence_into(
    mask: &[u32],
    n: u32,
    parent: &mut Vec<u32>,
    rank: &mut Vec<u32>,
) -> (u32, u32, u32) {
    let n_us = n as usize;
    assert_eq!(
        mask.len(),
        n_us * n_us,
        "Fix: betti_persistence requires mask of length n*n."
    );
    if n == 0 {
        parent.clear();
        rank.clear();
        return (0, 0, 0);
    }

    parent.clear();
    parent.extend(0..n);
    rank.clear();
    rank.resize(n_us, 0);

    let mut edges: u32 = 0;
    let mut tree_edges: u32 = 0;
    for i in 0..n_us {
        for j in (i + 1)..n_us {
            if mask[i * n_us + j] == 0 {
                continue;
            }
            edges = edges.saturating_add(1);
            if union(parent, rank, i as u32, j as u32) {
                tree_edges = tree_edges.saturating_add(1);
            }
        }
    }

    let mut b0 = 0u32;
    for v in 0..n {
        if find(parent, v) == v {
            b0 = b0.saturating_add(1);
        }
    }
    (b0, edges - tree_edges, edges)
}

fn find(parent: &mut [u32], mut x: u32) -> u32 {
    while parent[x as usize] != x {
        let p = parent[x as usize];
        parent[x as usize] = parent[p as usize];
        x = parent[x as usize];
    }
    x
}

fn union(parent: &mut [u32], rank: &mut [u32], a: u32, b: u32) -> bool {
    let ra = find(parent, a);
    let rb = find(parent, b);
    if ra == rb {
        return false;
    }
    let (ra_rank, rb_rank) = (rank[ra as usize], rank[rb as usize]);
    match ra_rank.cmp(&rb_rank) {
        std::cmp::Ordering::Less => parent[ra as usize] = rb,
        std::cmp::Ordering::Greater => parent[rb as usize] = ra,
        std::cmp::Ordering::Equal => {
            parent[rb as usize] = ra;
            rank[ra as usize] = ra_rank + 1;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_primitives::topology::betti_persistence::betti_persistence_cpu;

    #[test]
    fn empty_skeleton_below_threshold() {
        // 2 nodes at distance 1.0; ε = 0.5 yields no edges.
        let dist = vec![0.0, 1.0, 1.0, 0.0];
        let mask = region_loop_skeleton(&dist, 0.5, 2);
        assert!(mask.iter().all(|&v| v == 0));
    }

    #[test]
    fn full_skeleton_above_threshold() {
        // 3 nodes, all at distance 0.5 from each other.
        let dist = vec![0.0, 0.5, 0.5, 0.5, 0.0, 0.5, 0.5, 0.5, 0.0];
        let mask = region_loop_skeleton(&dist, 0.6, 3);
        // 3 edges in upper triangle: (0,1), (0,2), (1,2).
        let count: u32 = mask.iter().filter(|&&v| v != 0).count() as u32;
        assert_eq!(count, 3);
    }

    #[test]
    fn edges_extracted_in_canonical_order() {
        let dist = vec![0.0, 0.3, 0.7, 0.3, 0.0, 0.4, 0.7, 0.4, 0.0];
        let edges = region_loop_edges(&dist, 0.5, 3);
        // Distances ≤ 0.5: (0,1) at 0.3; (1,2) at 0.4. (0,2) excluded.
        assert!(edges.contains(&(0, 1)));
        assert!(edges.contains(&(1, 2)));
        assert!(!edges.contains(&(0, 2)));
    }

    #[test]
    fn filtration_edge_counts_monotone_increasing() {
        // As ε grows, edge count should be non-decreasing.
        let dist = vec![0.0, 0.1, 0.5, 0.1, 0.0, 0.2, 0.5, 0.2, 0.0];
        let epsilons = vec![0.05, 0.15, 0.25, 0.6];
        let counts = loop_filtration_edge_counts(&dist, &epsilons, 3);
        for w in counts.windows(2) {
            assert!(
                w[0] <= w[1],
                "edge counts must be monotone over ε filtration"
            );
        }
        // Final ε should reach 3 edges.
        assert_eq!(counts[3], 3);
    }

    #[test]
    fn singleton_dist_yields_no_edges() {
        let dist = vec![0.0];
        let mask = region_loop_skeleton(&dist, 1.0, 1);
        assert!(mask.iter().all(|&v| v == 0));
    }

    // ---- betti consumer ----

    #[test]
    fn betti_filtration_below_threshold_no_cycles() {
        // 3 nodes far apart; ε small → no edges, b0=3, b1=0.
        let dist = vec![0.0, 1.0, 1.0, 1.0, 0.0, 1.0, 1.0, 1.0, 0.0];
        let series = loop_filtration_betti(&dist, &[0.5], 3);
        assert_eq!(series, vec![(3, 0)]);
    }

    #[test]
    fn betti_filtration_triangle_has_b1_one() {
        // 3 nodes in equilateral triangle; ε large → triangle 1-skeleton.
        let dist = vec![0.0, 0.5, 0.5, 0.5, 0.0, 0.5, 0.5, 0.5, 0.0];
        let series = loop_filtration_betti(&dist, &[0.6], 3);
        // 3 edges, 1 component, 1 cycle.
        assert_eq!(series, vec![(1, 1)]);
    }

    #[test]
    fn betti_filtration_b1_monotone_non_decreasing_on_growing_filtration() {
        // 4 nodes; distances chosen so adding edges never breaks cycles.
        // (Edges only added; an existing cycle persists in a 1-skeleton.)
        let dist = vec![
            0.0, 0.1, 0.2, 0.3, // 0 -> {1,2,3}
            0.1, 0.0, 0.4, 0.5, // 1 -> {0,2,3}
            0.2, 0.4, 0.0, 0.6, // 2 -> {0,1,3}
            0.3, 0.5, 0.6, 0.0, // 3 -> {0,1,2}
        ];
        let epsilons = vec![0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65];
        let series = loop_filtration_betti(&dist, &epsilons, 4);
        for w in series.windows(2) {
            assert!(
                w[0].1 <= w[1].1,
                "b1 must be non-decreasing across a growing filtration; got {:?}",
                series
            );
        }
        // Final ε engulfs every pair: K4 has b1 = 3.
        assert_eq!(series.last().unwrap().1, 3);
    }

    #[test]
    fn betti_h1_birth_scales_pinpoints_first_cycle() {
        // 3 nodes; distances 0.1 (0,1), 0.2 (0,2), 0.3 (1,2).
        // ε=0.15 → only (0,1) edge → b1=0.
        // ε=0.25 → (0,1)+(0,2) edges → b1=0 (tree).
        // ε=0.35 → all three edges → b1=1 (triangle).
        let dist = vec![0.0, 0.1, 0.2, 0.1, 0.0, 0.3, 0.2, 0.3, 0.0];
        let epsilons = vec![0.15, 0.25, 0.35];
        let births = h1_birth_scales(&dist, &epsilons, 3);
        assert_eq!(births, vec![(0.35, 1)]);
    }

    #[test]
    fn filtration_into_paths_match_owned_helpers() {
        let dist = vec![0.0, 0.1, 0.2, 0.1, 0.0, 0.3, 0.2, 0.3, 0.0];
        let epsilons = vec![0.15, 0.25, 0.35];
        let mut scratch = LoopTopologyScratch::default();

        let owned_counts = loop_filtration_edge_counts(&dist, &epsilons, 3);
        let mut counts = Vec::new();
        loop_filtration_edge_counts_into(&dist, &epsilons, 3, &mut scratch, &mut counts);
        assert_eq!(counts, owned_counts);

        let owned_betti = loop_filtration_betti(&dist, &epsilons, 3);
        let mut betti = Vec::new();
        loop_filtration_betti_into(&dist, &epsilons, 3, &mut scratch, &mut betti);
        assert_eq!(betti, owned_betti);

        let owned_births = h1_birth_scales(&dist, &epsilons, 3);
        let mut births = Vec::new();
        h1_birth_scales_into(&dist, &epsilons, 3, &mut scratch, &mut births);
        assert_eq!(births, owned_births);
    }

    /// Closure-bar: `loop_filtration_betti` must produce identical
    /// (b0, b1) tuples to the underlying primitive when called on the
    /// same edge mask. If the consumer ever drifts (e.g. computes b1
    /// from edge count alone) this test fails.
    #[test]
    fn betti_filtration_matches_primitive_on_each_epsilon() {
        let dist = vec![
            0.0, 0.2, 0.4, 0.2, 0.0, 0.3, 0.4, 0.3, 0.0, // K3 with mixed dists
        ];
        let epsilons = vec![0.1, 0.25, 0.35, 0.5];
        let series = loop_filtration_betti(&dist, &epsilons, 3);
        for (idx, &eps) in epsilons.iter().enumerate() {
            let mask = region_loop_skeleton(&dist, eps, 3);
            let (b0_p, b1_p, _) = betti_persistence_cpu(&mask, 3);
            assert_eq!(series[idx], (b0_p, b1_p));
        }
    }

    /// Adversarial: a disjoint pair of triangles must have b1 = 2 at a
    /// scale that includes both triangles' edges. Naive code that only
    /// counts cycles within one component would fail.
    #[test]
    fn betti_adversarial_two_disjoint_triangles_has_b1_two() {
        // 6 nodes split into two disjoint triangles.
        // Within each triangle: pairwise distance 0.4.
        // Across triangles: pairwise distance 5.0 (never connect).
        let mut dist = vec![5.0; 36];
        for i in 0..6 {
            dist[i * 6 + i] = 0.0;
        }
        for &(i, j) in &[(0, 1), (0, 2), (1, 2), (3, 4), (3, 5), (4, 5)] {
            dist[i * 6 + j] = 0.4;
            dist[j * 6 + i] = 0.4;
        }
        let series = loop_filtration_betti(&dist, &[0.5], 6);
        let (b0, b1) = series[0];
        assert_eq!((b0, b1), (2, 2));
    }

    /// Adversarial: an empty epsilons slice must yield an empty
    /// series, not panic and not allocate phantom entries.
    #[test]
    fn betti_filtration_empty_epsilons_returns_empty() {
        let dist = vec![0.0, 0.1, 0.1, 0.0];
        let series = loop_filtration_betti(&dist, &[], 2);
        assert!(series.is_empty());
        let births = h1_birth_scales(&dist, &[], 2);
        assert!(births.is_empty());
    }
}
