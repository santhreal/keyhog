//! Autotuner gradient direction via #56 natural_gradient (#56 self-consumer).
//!
//! Closes the recursion thesis for #56 — natural_gradient ships to
//! user dialects (KFAC-trained NNs, Fisher-information-aware
//! optimizers) AND drives vyre's autotuner past the
//! `differentiable_autotune` baseline by using the Fisher-information
//! manifold's local geometry instead of plain gradient descent.
//!
//! # The self-use
//!
//! Vyre's autotuner (`differentiable_autotune` self-consumer)
//! computes a smoothed-argmax over kernel-config samples. The
//! gradient direction it follows is the plain Euclidean gradient
//! of latency w.r.t. config parameters. This converges slowly when
//! the latency surface has elongated valleys (typical: launch-cost
//! varies fast in workgroup-x, slow in y/z).
//!
//! Natural gradient preconditions the gradient by the inverse
//! Fisher information — the Riemannian gradient on the
//! parameter manifold. Empirically, KFAC-style block-diagonal
//! Fisher approximation gives 5-10× faster convergence than
//! plain gradient on the same configuration-tuning surfaces.
//!
//! # Algorithm
//!
//! ```text
//! 1. compute plain gradient g = ∂latency/∂config (already exists)
//! 2. compute Fisher block M = Var(∂log_latency/∂config)
//!    over recent autotune samples
//! 3. M_inv_sqrt = inverse square root of M (host-side
//!    Newton-Schulz iteration → vyre-primitives::math::preconditioner)
//! 4. g_nat = natural_gradient_block_apply(M_inv_sqrt, g)
//!    → preconditioned step direction
//! 5. autotuner takes step in g_nat direction instead of g
//! ```
//!
//! This module owns the natural-gradient apply step. Callers provide
//! the Fisher block they want to use, whether estimated on the host,
//! read from telemetry, or produced by another registered primitive.

use vyre_primitives::math::natural_gradient::{
    natural_gradient_block_apply_cpu, natural_gradient_block_apply_cpu_into,
};

/// Apply the inverse-Fisher preconditioner to a plain gradient,
/// yielding the natural gradient `g_nat = M_inv_sqrt · g`. The
/// autotuner then takes a step in the `g_nat` direction.
///
/// `m_inv_sqrt` is the inverse square root of the Fisher block
/// (n × n row-major); `grad` is the plain gradient (length n).
///
/// # Panics
///
/// Panics if `m_inv_sqrt.len() != n*n` or `grad.len() != n`.
#[must_use]
pub fn precondition_autotune_gradient(m_inv_sqrt: &[f64], grad: &[f64], n: u32) -> Vec<f64> {
    use crate::observability::{bump, natural_gradient_autotuner_calls};
    bump(&natural_gradient_autotuner_calls);
    natural_gradient_block_apply_cpu(m_inv_sqrt, grad, n)
}

/// Apply the inverse-Fisher preconditioner into caller-owned output.
pub fn precondition_autotune_gradient_into(
    m_inv_sqrt: &[f64],
    grad: &[f64],
    n: u32,
    out: &mut Vec<f64>,
) {
    use crate::observability::{bump, natural_gradient_autotuner_calls};
    bump(&natural_gradient_autotuner_calls);
    natural_gradient_block_apply_cpu_into(m_inv_sqrt, grad, n, out);
}

/// Compute the autotuner step from a plain gradient and learning
/// rate, with Fisher preconditioning. Returns the parameter delta:
/// `delta = -lr · g_nat`.
#[must_use]
pub fn autotune_step(m_inv_sqrt: &[f64], grad: &[f64], n: u32, learning_rate: f64) -> Vec<f64> {
    let mut out = Vec::new();
    autotune_step_into(m_inv_sqrt, grad, n, learning_rate, &mut out);
    out
}

/// Compute the autotuner step into caller-owned output.
pub fn autotune_step_into(
    m_inv_sqrt: &[f64],
    grad: &[f64],
    n: u32,
    learning_rate: f64,
    out: &mut Vec<f64>,
) {
    precondition_autotune_gradient_into(m_inv_sqrt, grad, n, out);
    for value in out.iter_mut() {
        *value *= -learning_rate;
    }
}

/// Convenience: identity Fisher block. When the autotuner has no
/// curvature information yet (cold start), pass this so the natural
/// gradient reduces to the plain gradient.
#[must_use]
pub fn identity_fisher_block(n: u32) -> Vec<f64> {
    let mut out = Vec::new();
    identity_fisher_block_into(n, &mut out);
    out
}

/// Write an identity Fisher block into caller-owned storage.
pub fn identity_fisher_block_into(n: u32, out: &mut Vec<f64>) {
    let n_us = n as usize;
    out.clear();
    out.resize(n_us * n_us, 0.0);
    for i in 0..n_us {
        out[i * n_us + i] = 1.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9 * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn identity_fisher_recovers_plain_gradient() {
        let id = identity_fisher_block(3);
        let grad = vec![1.0, -2.0, 0.5];
        let g_nat = precondition_autotune_gradient(&id, &grad, 3);
        for (a, b) in grad.iter().zip(g_nat.iter()) {
            assert!(approx_eq(*a, *b));
        }
    }

    #[test]
    fn autotune_step_negates_gradient() {
        let id = identity_fisher_block(2);
        let grad = vec![1.0, 2.0];
        let step = autotune_step(&id, &grad, 2, 0.1);
        // step = -0.1 * grad.
        assert!(approx_eq(step[0], -0.1));
        assert!(approx_eq(step[1], -0.2));
    }

    #[test]
    fn autotune_step_zero_lr_no_motion() {
        let id = identity_fisher_block(3);
        let grad = vec![1.0, 2.0, 3.0];
        let step = autotune_step(&id, &grad, 3, 0.0);
        for v in step {
            assert!(approx_eq(v, 0.0));
        }
    }

    #[test]
    fn autotune_step_into_reuses_output() {
        let id = identity_fisher_block(2);
        let grad = vec![1.0, 2.0];
        let mut step = Vec::with_capacity(8);
        let ptr = step.as_ptr();
        autotune_step_into(&id, &grad, 2, 0.1, &mut step);
        assert!(approx_eq(step[0], -0.1));
        assert!(approx_eq(step[1], -0.2));
        assert_eq!(step.as_ptr(), ptr);
    }

    #[test]
    fn diagonal_fisher_scales_per_axis() {
        // Anisotropic: x scaled by 1.0, y scaled by 4.0.
        // M_inv_sqrt = diag(1, 0.5).
        let m_inv_sqrt = vec![1.0, 0.0, 0.0, 0.5];
        let grad = vec![10.0, 10.0];
        let g_nat = precondition_autotune_gradient(&m_inv_sqrt, &grad, 2);
        // Natural gradient pulls back the steep y axis:
        //   g_nat = (10, 5).
        assert!(approx_eq(g_nat[0], 10.0));
        assert!(approx_eq(g_nat[1], 5.0));
    }

    #[test]
    fn identity_fisher_block_is_diagonal_of_ones() {
        let id = identity_fisher_block(4);
        for i in 0..4 {
            assert!(approx_eq(id[i * 4 + i], 1.0));
            for j in 0..4 {
                if i != j {
                    assert!(approx_eq(id[i * 4 + j], 0.0));
                }
            }
        }
    }
}
