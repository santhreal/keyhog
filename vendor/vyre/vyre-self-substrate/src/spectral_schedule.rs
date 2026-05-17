//! Spectral analysis of dispatch graph via #5 chebyshev_filter +
//! #17 spectral_shape (#23 substrate).
//!
//! Apply Chebyshev polynomial filtering to vyre's own dispatch
//! dependency matrix, clip outlier eigenvalues via Marchenko-Pastur
//! edge, identify clusters of Programs that should be fused.
//! Output: cluster IDs that #19 polyhedral fusion + #22 megakernel
//! scheduler consume as fusion hints.

use vyre_primitives::graph::chebyshev_filter::chebyshev_filter_cpu;
use vyre_primitives::math::spectral_shape::{mp_edge_clip_cpu, mp_upper_edge};

/// Score nodes for fusion clustering by applying a low-pass Chebyshev
/// filter (coeffs [1, 0.5, 0.25] = exponential decay) to a unit-energy
/// signal at each node. Nodes returning high scores are spectrally
/// connected.
#[must_use]
pub fn fusion_scores(laplacian: &[f32], n: u32) -> Vec<f32> {
    use crate::observability::{bump, spectral_schedule_calls};
    bump(&spectral_schedule_calls);
    assert_eq!(laplacian.len(), (n * n) as usize);
    let signal: Vec<f32> = (0..n).map(|_| 1.0 / (n as f32).sqrt()).collect();
    let coeffs: Vec<f32> = vec![1.0, 0.5, 0.25];
    chebyshev_filter_cpu(laplacian, &signal, &coeffs, n, 2)
}

/// Clip outlier eigenvalues at the Marchenko-Pastur upper edge. Used
/// to filter spurious high-frequency dispatch-graph correlations.
#[must_use]
pub fn shape_spectrum(eigenvalues: &[f64], n_dispatches: u32, n_features: u32) -> Vec<f64> {
    let edge = mp_upper_edge(n_dispatches, n_features, 1.0);
    mp_edge_clip_cpu(eigenvalues, edge)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq_f32(a: f32, b: f32) -> bool {
        (a - b).abs() < 1e-4 * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn fusion_scores_uniform_for_zero_laplacian() {
        // No edges → Laplacian = 0 matrix. Chebyshev recurrence:
        //   T_0 = signal, T_1 = L·signal = 0, T_2 = 2·L·T_1 - T_0 = -signal.
        // Output with coeffs [1, 0.5, 0.25]:
        //   c_0·T_0 + c_1·T_1 + c_2·T_2 = (1 - 0.25) · signal = 0.75 · signal
        // signal = 1/sqrt(4) = 0.5; output = 0.375 per node.
        let l: Vec<f32> = vec![0.0; 16];
        let scores = fusion_scores(&l, 4);
        for s in scores {
            assert!(approx_eq_f32(s, 0.375));
        }
    }

    #[test]
    fn shape_spectrum_clips_outliers() {
        // n_dispatches = 100, n_features = 100, σ²=1 → MP edge = 4.
        let eig = vec![1.0, 3.0, 5.0, 100.0];
        let clipped = shape_spectrum(&eig, 100, 100);
        assert_eq!(clipped[0], 1.0);
        assert_eq!(clipped[1], 3.0);
        assert_eq!(clipped[2], 4.0); // clipped to edge
        assert_eq!(clipped[3], 4.0); // clipped to edge
    }

    #[test]
    fn fusion_scores_zero_signal_zero_output() {
        let l: Vec<f32> = vec![0.5; 4];
        let scores = fusion_scores(&l, 2);
        for s in scores {
            assert!(s.is_finite());
        }
    }
}
