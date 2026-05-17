//! RMT-based deterministic spectrum projection primitive (#17).
//!
//! Random matrix theory predicts the bulk spectrum of large random
//! matrices (Marchenko-Pastur, Wigner). Recent work (Pennington 2017,
//! Martin 2021 weight-watcher, Edelman 2024) uses RMT to PREDICT
//! training dynamics and SHAPE the weight spectrum. This file ships
//! the **Marchenko-Pastur edge-clipping** primitive — given the
//! eigenvalue/singular-value distribution of a matrix, clip values
//! outside the predicted bulk to the bulk-edge.
//!
//! Composes with #5 chebyshev_filter for the spectrum projection
//! without computing the eigendecomposition.
//!
//! # Why this primitive is dual-use
//!
//! | Consumer | Use |
//! |---|---|
//! | future `vyre-libs::ml::implicit_reg` | implicit regularization without hyperparameters |
//! | future `vyre-libs::ml::training_dynamics` | training-dynamics-aware optimizers |
//! | `vyre-foundation::transform` spectral scheduling | clip outlier eigenvalues in vyre's dispatch graph |

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Op id.
pub const OP_ID: &str = "vyre-primitives::math::mp_edge_clip";

/// Marchenko-Pastur upper edge: `(1 + √(p/n))²` where `p, n` are
/// matrix dimensions and `σ²` = entry variance. The caller passes a
/// scaled upper bound `mp_edge` (16.16 fp).
///
/// Emit: clip each eigenvalue to `min(mp_edge, eigenvalue)`.
#[must_use]
pub fn mp_edge_clip(eigenvalues: &str, mp_edge: &str, out: &str, n: u32) -> Program {
    if n == 0 {
        return crate::invalid_output_program(
            OP_ID,
            out,
            DataType::U32,
            format!("Fix: mp_edge_clip requires n > 0, got {n}."),
        );
    }

    let t = Expr::InvocationId { axis: 0 };
    let bound = Expr::load(mp_edge, Expr::u32(0));
    let value = Expr::min(Expr::load(eigenvalues, t.clone()), bound);

    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(n)),
        vec![Node::store(out, t, value)],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(eigenvalues, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n),
            BufferDecl::storage(mp_edge, 1, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage(out, 2, BufferAccess::ReadWrite, DataType::U32).with_count(n),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// Compute the Marchenko-Pastur upper edge for an `m × n` matrix with
/// entry variance `sigma_sq`.
#[must_use]
pub fn mp_upper_edge(m: u32, n: u32, sigma_sq: f64) -> f64 {
    if m == 0 || n == 0 {
        return f64::NAN;
    }
    let q = (m.min(n) as f64) / (m.max(n) as f64);
    let factor = (1.0 + q.sqrt()).powi(2);
    sigma_sq * factor
}

/// CPU reference: clip elementwise to the MP edge.
#[must_use]
pub fn mp_edge_clip_cpu(eigenvalues: &[f64], edge: f64) -> Vec<f64> {
    eigenvalues.iter().map(|&v| v.min(edge)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-10 * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn cpu_mp_edge_square_matrix() {
        // m = n = 100, σ² = 1 → MP edge = 4 (since q = 1, factor = (1+1)² = 4)
        let edge = mp_upper_edge(100, 100, 1.0);
        assert!(approx_eq(edge, 4.0));
    }

    #[test]
    fn cpu_mp_edge_tall_matrix() {
        // m = 100, n = 25, σ² = 1, q = 0.25 → factor = (1+0.5)² = 2.25
        let edge = mp_upper_edge(100, 25, 1.0);
        assert!(approx_eq(edge, 2.25));
    }

    #[test]
    fn cpu_clip_below_edge_unchanged() {
        let eig = vec![1.0, 2.0, 3.0];
        let out = mp_edge_clip_cpu(&eig, 4.0);
        assert_eq!(out, eig);
    }

    #[test]
    fn cpu_clip_above_edge_clamped() {
        let eig = vec![1.0, 5.0, 10.0];
        let out = mp_edge_clip_cpu(&eig, 4.0);
        assert!(approx_eq(out[0], 1.0));
        assert!(approx_eq(out[1], 4.0));
        assert!(approx_eq(out[2], 4.0));
    }

    #[test]
    fn ir_program_buffer_layout() {
        let p = mp_edge_clip("e", "edge", "out", 16);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        assert_eq!(p.buffers[0].count(), 16);
        assert_eq!(p.buffers[1].count(), 1);
        assert_eq!(p.buffers[2].count(), 16);
    }

    #[test]
    fn zero_n_traps() {
        let p = mp_edge_clip("e", "edge", "out", 0);
        assert!(p.stats().trap());
    }
}
