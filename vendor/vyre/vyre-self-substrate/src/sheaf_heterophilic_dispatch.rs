//! Heterophilic dispatch-graph analysis via #31 sheaf diffusion (#31 self-consumer).
//!
//! Closes the recursion thesis for #31 — sheaf neural networks
//! ship to user dialects (heterophilic graph learning, social
//! networks, code call graphs) AND directly model vyre's own
//! dispatch graph, where compute-bound, memory-bound, and
//! control-flow nodes have fundamentally different "feature spaces"
//! that GNN-style isotropic diffusion can't capture.
//!
//! # The legendary self-use
//!
//! Vyre's dispatch graph is heterophilic by construction:
//!
//! - **Compute-bound nodes** (FFT, gemm) have feature dimensions
//!   {flops, register pressure, ALU utilization}.
//! - **Memory-bound nodes** (load/store/copy) have features
//!   {bytes/sec, cache hit rate, DRAM utilization}.
//! - **Control-flow nodes** (If, Loop) have features
//!   {branch divergence, predicate cost, scheduling fence count}.
//!
//! These three feature spaces are NOT comparable — flops/sec is
//! not the same kind of thing as bytes/sec. Standard GNN
//! homophilic diffusion would average across these heterogeneous
//! kinds and produce nonsense.
//!
//! Sheaf neural networks (Bodnar-Di Giovanni 2022,
//! Hansen-Gebhart 2023) generalize: each node carries its OWN
//! vector space + restriction maps to neighbors. The sheaf
//! Laplacian respects the heterogeneity. Diffusion on the sheaf
//! Laplacian preserves type-correctness.
//!
//! For vyre, sheaf diffusion on the dispatch graph PREDICTS where
//! fusion will fail: nodes whose stalks diverge under sheaf
//! diffusion are nodes whose feature spaces don't align — fusing
//! them requires a costly conversion shim.
//!
//! # Algorithm
//!
//! ```text
//! 1. assign each Region a stalk vector in its node-type's feature
//!    space
//! 2. compute the restriction diagonal — how strongly each Region
//!    "transmits" features to neighbors (high = compatible types,
//!    low = type-mismatch)
//! 3. one or more sheaf_diffusion_step iterations
//! 4. nodes whose stalks DIVERGE from neighbors after diffusion are
//!    flagged as fusion-incompatible
//! ```
//!
//! # Why this matters
//!
//! Today vyre's fusion analyzer treats the dispatch graph as
//! homogeneous — every Region looks the same to the scheduler.
//! Sheaf-diffusion-driven fusion analysis is the FIRST GPU
//! substrate to model dispatch graphs as the heterophilic
//! structures they actually are. Paradigm shift, not optimization.

use vyre_primitives::graph::sheaf::{sheaf_diffusion_step_cpu, sheaf_diffusion_step_cpu_into};

/// Apply one sheaf-diffusion step to dispatch-graph stalks.
/// `stalks[i]` is Region i's feature scalar (in its own type's
/// feature space); `restriction_diag[i]` is the per-Region
/// transmission coefficient (high = compatible neighbor types,
/// low = mismatch). `damping` is the diffusion rate in `[0, 1]`.
///
/// Returns the diffused stalks.
#[must_use]
pub fn diffuse_dispatch_stalks(stalks: &[f64], restriction_diag: &[f64], damping: f64) -> Vec<f64> {
    use crate::observability::{bump, sheaf_heterophilic_dispatch_calls};
    bump(&sheaf_heterophilic_dispatch_calls);
    sheaf_diffusion_step_cpu(stalks, restriction_diag, damping)
}

/// Apply one sheaf-diffusion step into caller-owned storage.
///
/// Clears `out` and reuses its allocation.
pub fn diffuse_dispatch_stalks_into(
    stalks: &[f64],
    restriction_diag: &[f64],
    damping: f64,
    out: &mut Vec<f64>,
) {
    use crate::observability::{bump, sheaf_heterophilic_dispatch_calls};
    bump(&sheaf_heterophilic_dispatch_calls);
    sheaf_diffusion_step_cpu_into(stalks, restriction_diag, damping, out);
}

/// Iterate sheaf diffusion until convergence (stalks stop changing
/// to within `tol`) or `max_iters` is reached. Returns
/// `(final_stalks, iters_run)`.
#[must_use]
pub fn diffuse_to_equilibrium(
    initial_stalks: &[f64],
    restriction_diag: &[f64],
    damping: f64,
    tol: f64,
    max_iters: u32,
) -> (Vec<f64>, u32) {
    let mut current = Vec::with_capacity(initial_stalks.len());
    let mut next = Vec::with_capacity(initial_stalks.len());
    let iters = diffuse_to_equilibrium_into(
        initial_stalks,
        restriction_diag,
        damping,
        tol,
        max_iters,
        &mut current,
        &mut next,
    );
    (current, iters)
}

/// Iterate sheaf diffusion into caller-owned storage.
///
/// `out` receives the final stalk vector and `scratch` is reused for each
/// intermediate step.
pub fn diffuse_to_equilibrium_into(
    initial_stalks: &[f64],
    restriction_diag: &[f64],
    damping: f64,
    tol: f64,
    max_iters: u32,
    out: &mut Vec<f64>,
    scratch: &mut Vec<f64>,
) -> u32 {
    out.clear();
    out.extend_from_slice(initial_stalks);
    for iter in 0..max_iters {
        diffuse_dispatch_stalks_into(out, restriction_diag, damping, scratch);
        let max_change = scratch
            .iter()
            .zip(out.iter())
            .map(|(a, b)| (a - b).abs())
            .fold(0.0_f64, f64::max);
        std::mem::swap(out, scratch);
        if max_change < tol {
            return iter + 1;
        }
    }
    max_iters
}

/// Identify fusion-incompatible Region pairs: high stalk divergence
/// after diffusion = type-space mismatch. Returns a 0/1 vector;
/// 1 means "this Region's stalk diverged enough to flag fusion-incompatible."
#[must_use]
pub fn flag_fusion_incompatible(
    initial_stalks: &[f64],
    diffused_stalks: &[f64],
    divergence_threshold: f64,
) -> Vec<u32> {
    let mut out = Vec::new();
    flag_fusion_incompatible_into(
        initial_stalks,
        diffused_stalks,
        divergence_threshold,
        &mut out,
    );
    out
}

/// Identify fusion-incompatible Region pairs into caller-owned storage.
pub fn flag_fusion_incompatible_into(
    initial_stalks: &[f64],
    diffused_stalks: &[f64],
    divergence_threshold: f64,
    out: &mut Vec<u32>,
) {
    out.clear();
    out.reserve(initial_stalks.len());
    initial_stalks
        .iter()
        .zip(diffused_stalks.iter())
        .map(|(&i, &d)| {
            if (i - d).abs() > divergence_threshold {
                1u32
            } else {
                0u32
            }
        })
        .for_each(|flag| out.push(flag));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9 * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn zero_damping_holds_initial() {
        let s = vec![1.0, 2.0, 3.0];
        let r = vec![0.5, 0.5, 0.5];
        let out = diffuse_dispatch_stalks(&s, &r, 0.0);
        for (a, b) in s.iter().zip(out.iter()) {
            assert!(approx_eq(*a, *b));
        }
    }

    #[test]
    fn high_damping_drives_to_equilibrium() {
        let s = vec![1.0, 1.0, 1.0];
        let r = vec![1.0, 1.0, 1.0];
        let (final_stalks, iters) = diffuse_to_equilibrium(&s, &r, 0.9, 1e-6, 100);
        // High damping + uniform restriction collapses stalks toward 0.
        assert!(final_stalks.iter().all(|&v| v.abs() < 1.0));
        assert!(iters < 100);
    }

    #[test]
    fn flag_fusion_incompatible_threshold_zero_flags_all_changes() {
        let initial = vec![1.0, 2.0, 3.0];
        let diffused = vec![0.5, 2.0, 2.5];
        let flags = flag_fusion_incompatible(&initial, &diffused, 0.0);
        // 0 != 0.5 → flag; 2 == 2 → no flag; 3 != 2.5 → flag.
        assert_eq!(flags, vec![1, 0, 1]);
    }

    #[test]
    fn high_threshold_flags_nothing() {
        let initial = vec![1.0, 2.0];
        let diffused = vec![1.5, 2.5];
        let flags = flag_fusion_incompatible(&initial, &diffused, 100.0);
        assert_eq!(flags, vec![0, 0]);
    }

    #[test]
    fn flag_fusion_incompatible_into_reuses_buffer() {
        let initial = vec![1.0, 2.0, 3.0];
        let diffused = vec![0.5, 2.0, 2.5];
        let mut flags = Vec::with_capacity(8);
        let ptr = flags.as_ptr();
        flag_fusion_incompatible_into(&initial, &diffused, 0.0, &mut flags);
        assert_eq!(flags, vec![1, 0, 1]);
        assert_eq!(flags.as_ptr(), ptr);
    }

    #[test]
    fn equilibrium_with_zero_max_iters_returns_initial() {
        let s = vec![5.0, 10.0];
        let r = vec![1.0, 1.0];
        let (out, iters) = diffuse_to_equilibrium(&s, &r, 0.5, 1e-6, 0);
        assert_eq!(out, s);
        assert_eq!(iters, 0);
    }
}
