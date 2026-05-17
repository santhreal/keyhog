//! Sheaf-spectral clustering of dispatch graphs.
//!
//! Self-consumer for [#9 `sheaf_laplacian_eigenvalue`](vyre_primitives::math::sheaf_laplacian_eigenvalue).
//!
//! The dispatch graph's sheaf Laplacian carries spectral information
//! about cluster structure: the dominant eigenvalue corresponds to
//! the longest principal direction of the graph's heterophilic
//! diffusion. Combined with the existing
//! [`super::sheaf_heterophilic_dispatch::flag_fusion_incompatible`]
//! divergence flagging, this gives:
//!
//! - **Spectral gap** — eigenvalue magnitude indicates how cleanly
//!   the graph splits into clusters. Large gap = clean clusters,
//!   safe to fuse within each cluster.
//! - **Suggested cluster count** — derived from the eigenvalue
//!   spectrum via the substrate's power-iteration diagonal output.
//!
//! Used by the megakernel scheduler when the matroid heuristic
//! produces ambiguous results (many tied gain values) — falls back
//! to spectral cluster suggestions for tie-breaking.

use vyre_primitives::math::sheaf_laplacian_eigenvalue::cpu_ref_into;

/// Default power-iteration count for spectral cluster signal.
/// 32 iterations converges the dominant eigenvalue to <1e-6 relative
/// error on dispatch graphs we've measured (n ≤ 256).
pub const DEFAULT_POWER_ITERATIONS: u32 = 32;

/// Reusable buffers for sheaf-spectral power iteration.
#[derive(Debug, Default)]
pub struct SheafSpectrumScratch {
    v_init: Vec<f64>,
    v: Vec<f64>,
    v_next: Vec<f64>,
}

impl SheafSpectrumScratch {
    /// Dominant eigenvector from the last spectral solve.
    #[must_use]
    pub fn eigenvector(&self) -> &[f64] {
        &self.v
    }
}

/// Compute the dominant eigenvalue + eigenvector of the dispatch
/// graph's sheaf Laplacian. The eigenvalue magnitude is the spectral
/// gap signal; the eigenvector indicates which work items lie on the
/// principal cluster boundary.
///
/// `restriction_diag[i]` is the per-item transmission coefficient
/// from the existing
/// [`super::sheaf_heterophilic_dispatch`] wire. Pass the same vector
/// the diffusion step uses.
///
/// Returns `(dominant_eigenvalue, eigenvector)` of length `n`.
#[must_use]
pub fn dominant_spectrum(restriction_diag: &[f64], iterations: u32) -> (f64, Vec<f64>) {
    use crate::observability::{bump, sheaf_spectral_clustering_calls};
    bump(&sheaf_spectral_clustering_calls);
    let mut scratch = SheafSpectrumScratch::default();
    let lambda = dominant_spectrum_with_scratch(restriction_diag, iterations, &mut scratch);
    (lambda, scratch.v)
}

/// Compute the dominant eigenvalue using reusable spectral scratch.
pub fn dominant_spectrum_with_scratch(
    restriction_diag: &[f64],
    iterations: u32,
    scratch: &mut SheafSpectrumScratch,
) -> f64 {
    dominant_spectrum_into(
        restriction_diag,
        iterations,
        &mut scratch.v_init,
        &mut scratch.v,
        &mut scratch.v_next,
    )
}

/// Compute the dominant eigenvalue into caller-owned storage.
pub fn dominant_spectrum_into(
    restriction_diag: &[f64],
    iterations: u32,
    v_init: &mut Vec<f64>,
    v: &mut Vec<f64>,
    v_next: &mut Vec<f64>,
) -> f64 {
    let n = restriction_diag.len();
    if n == 0 {
        v_init.clear();
        v.clear();
        v_next.clear();
        return 0.0;
    }
    let inv_sqrt_n = 1.0 / (n as f64).sqrt();
    v_init.clear();
    v_init.resize(n, inv_sqrt_n);
    cpu_ref_into(restriction_diag, v_init, iterations, v, v_next)
}

/// Convenience: spectral gap signal in `[0, 1]` derived from the
/// dominant eigenvalue. Higher = cleaner cluster separation.
#[must_use]
pub fn spectral_gap(restriction_diag: &[f64]) -> f64 {
    let mut scratch = SheafSpectrumScratch::default();
    spectral_gap_into(restriction_diag, &mut scratch)
}

/// Compute spectral gap using caller-owned power-iteration scratch.
pub fn spectral_gap_into(restriction_diag: &[f64], scratch: &mut SheafSpectrumScratch) -> f64 {
    let lambda =
        dominant_spectrum_with_scratch(restriction_diag, DEFAULT_POWER_ITERATIONS, scratch);
    // Eigenvalues of a sheaf Laplacian on transmission diagonals are
    // bounded by max(restriction_diag); normalize to [0, 1].
    let max_diag = restriction_diag.iter().cloned().fold(0.0_f64, f64::max);
    if max_diag <= 1e-20 {
        0.0
    } else {
        (lambda / max_diag).clamp(0.0, 1.0)
    }
}

/// Derive a suggested cluster count from the principal eigenvector
/// sign pattern. Items whose eigenvector entry has the same sign
/// belong in the same cluster; flips between consecutive items
/// suggest cluster boundaries. Returns the count of distinct sign
/// runs (≥ 1).
#[must_use]
pub fn suggested_cluster_count(restriction_diag: &[f64]) -> u32 {
    let mut scratch = SheafSpectrumScratch::default();
    suggested_cluster_count_into(restriction_diag, &mut scratch)
}

/// Derive suggested cluster count using caller-owned spectral scratch.
pub fn suggested_cluster_count_into(
    restriction_diag: &[f64],
    scratch: &mut SheafSpectrumScratch,
) -> u32 {
    dominant_spectrum_with_scratch(restriction_diag, DEFAULT_POWER_ITERATIONS, scratch);
    let v = scratch.eigenvector();
    if v.is_empty() {
        return 0;
    }
    let mut count: u32 = 1;
    let mut last_sign = v[0].signum();
    for &x in v.iter().skip(1) {
        let sign = x.signum();
        if sign != 0.0 && sign != last_sign && last_sign != 0.0 {
            count = count.saturating_add(1);
            last_sign = sign;
        } else if last_sign == 0.0 && sign != 0.0 {
            last_sign = sign;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-3 * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn dominant_eigenvalue_of_uniform_diag_is_diag_value() {
        // restriction = [0.7, 0.7, 0.7, 0.7] → dominant eigenvalue = 0.7.
        let diag = vec![0.7, 0.7, 0.7, 0.7];
        let (lambda, _v) = dominant_spectrum(&diag, 64);
        assert!(approx_eq(lambda, 0.7), "got lambda={lambda}");
    }

    #[test]
    fn dominant_eigenvalue_of_nonuniform_picks_max() {
        // restriction = [0.1, 0.5, 0.9, 0.3] → dominant eigenvalue ≈ 0.9.
        let diag = vec![0.1, 0.5, 0.9, 0.3];
        let (lambda, v) = dominant_spectrum(&diag, 128);
        assert!((lambda - 0.9).abs() < 0.01, "got lambda={lambda}");
        // Eigenvector should localize on index 2 (the 0.9 entry).
        let max_idx = v
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.abs().partial_cmp(&b.1.abs()).unwrap())
            .map(|(i, _)| i)
            .unwrap_or(0);
        assert_eq!(max_idx, 2);
    }

    #[test]
    fn empty_input_returns_zero_spectrum() {
        let (lambda, v) = dominant_spectrum(&[], 32);
        assert_eq!(lambda, 0.0);
        assert!(v.is_empty());
    }

    #[test]
    fn spectral_gap_is_one_for_uniform_diag() {
        // Uniform diagonal — eigenvalue equals max — gap = 1.
        let diag = vec![0.5; 8];
        let gap = spectral_gap(&diag);
        assert!((gap - 1.0).abs() < 1e-3);
    }

    #[test]
    fn scratch_paths_match_owned_spectral_helpers() {
        let diag = vec![0.1, 0.5, 0.9, 0.3];
        let (owned_lambda, owned_v) = dominant_spectrum(&diag, 64);
        let mut scratch = SheafSpectrumScratch::default();
        let borrowed_lambda = dominant_spectrum_with_scratch(&diag, 64, &mut scratch);
        assert!(approx_eq(owned_lambda, borrowed_lambda));
        assert_eq!(scratch.eigenvector().len(), owned_v.len());

        let owned_gap = spectral_gap(&diag);
        let scratch_gap = spectral_gap_into(&diag, &mut scratch);
        assert!(approx_eq(owned_gap, scratch_gap));

        let owned_count = suggested_cluster_count(&diag);
        let scratch_count = suggested_cluster_count_into(&diag, &mut scratch);
        assert_eq!(owned_count, scratch_count);
    }

    #[test]
    fn suggested_cluster_count_at_least_one() {
        let diag = vec![0.7; 4];
        let count = suggested_cluster_count(&diag);
        assert!(count >= 1);
    }
}
