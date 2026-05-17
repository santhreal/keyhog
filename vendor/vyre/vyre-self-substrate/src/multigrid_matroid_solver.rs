//! Sparse linear-system solver for matroid intersection via #50
//! algebraic multigrid (#50 self-consumer).
//!
//! Closes the recursion thesis for #50 — Algebraic Multigrid (AMG)
//! Jacobi smoothing ships to user dialects (any PDE / sparse-system
//! workload) AND solves the inner linear systems that
//! Chakrabarty-Lee-Sidford (2021) reduces matroid intersection to.
//!
//! # The self-use
//!
//! Modern matroid-intersection algorithms (CLS-2021) reduce each
//! augmenting iteration to O(n²) iterations of solving sparse linear
//! systems M·x = b where M is the matroid-cover Laplacian.
//! Naive Gauss-Seidel takes O(n²) per step → O(n⁴) overall —
//! intractable at workspace scale.
//!
//! AMG V-cycle drops this to O(n) per step → O(n³) overall, AND
//! the V-cycle structure is GPU-shaped: each level's smoothing is
//! one Jacobi-iteration dispatch, the coarsening between levels
//! is one prolongation/restriction sparse-matmul.
//!
//! Combined with the matroid_megakernel_scheduler self-consumer:
//!
//! ```text
//! megakernel scheduler                  matroid intersection
//!         |                                      ^
//!         v                                      |
//!   homotopy continuous solver --rounds--> matroid intersection
//!                                                 |
//!                                                 v
//!                                     CLS-2021 sparse linear solve
//!                                                 |
//!                                                 v
//!                                     AMG V-cycle (this self-consumer)
//! ```
//!
//! Three-deep recursive substrate: scheduler → matroid → AMG.
//! Each layer's Tier-2.5 primitive is the substrate for the layer
//! above. The recursion thesis at its limit.
//!
//! # Algorithm
//!
//! This module owns the per-level Jacobi-smoothing step and the
//! host-side tolerance loop used by matroid-intersection callers. A
//! full V-cycle composes this step with explicit restriction and
//! prolongation primitives.

use vyre_primitives::math::multigrid::{jacobi_smooth_step_cpu, jacobi_smooth_step_cpu_into};

/// Apply one weighted-Jacobi smoothing step to the matroid linear
/// system. `a` is the n*n cover-Laplacian matrix; `b` is the rhs;
/// `x_in` is the current iterate; `omega` is the relaxation weight
/// (0.66 is the standard choice for pure Jacobi convergence on
/// Laplacian systems).
///
/// # Panics
///
/// Panics on size mismatches.
#[must_use]
pub fn matroid_solve_step(a: &[f64], b: &[f64], x_in: &[f64], omega: f64, n: u32) -> Vec<f64> {
    use crate::observability::{bump, multigrid_matroid_solver_calls};
    bump(&multigrid_matroid_solver_calls);
    jacobi_smooth_step_cpu(a, b, x_in, omega, n)
}

/// Apply one weighted-Jacobi smoothing step into caller-owned storage.
///
/// This is the hot path for tolerance loops; it avoids allocating a new
/// solution vector for every relaxation iteration.
pub fn matroid_solve_step_into(
    a: &[f64],
    b: &[f64],
    x_in: &[f64],
    omega: f64,
    n: u32,
    out: &mut Vec<f64>,
) {
    use crate::observability::{bump, multigrid_matroid_solver_calls};
    bump(&multigrid_matroid_solver_calls);
    jacobi_smooth_step_cpu_into(a, b, x_in, omega, n, out);
}

/// Iterate Jacobi smoothing until residual norm drops below `tol`
/// or `max_iters` reached. Returns `(x, iters_run)`.
///
/// The Tier-2.5 primitive ships the per-step kernel; the convergence
/// loop here is what production matroid-intersection callers want.
#[must_use]
pub fn solve_to_tolerance(
    a: &[f64],
    b: &[f64],
    x0: &[f64],
    omega: f64,
    n: u32,
    tol: f64,
    max_iters: u32,
) -> (Vec<f64>, u32) {
    let mut x = Vec::new();
    let mut next = Vec::new();
    let iters = solve_to_tolerance_into(a, b, x0, omega, n, tol, max_iters, &mut x, &mut next);
    (x, iters)
}

/// Iterate Jacobi smoothing into caller-owned buffers.
///
/// Returns the iteration count and leaves the final solution in `x`.
#[allow(clippy::too_many_arguments)]
pub fn solve_to_tolerance_into(
    a: &[f64],
    b: &[f64],
    x0: &[f64],
    omega: f64,
    n: u32,
    tol: f64,
    max_iters: u32,
    x: &mut Vec<f64>,
    next: &mut Vec<f64>,
) -> u32 {
    x.clear();
    x.extend_from_slice(x0);
    next.clear();
    let n_us = n as usize;
    for iter in 0..max_iters {
        matroid_solve_step_into(a, b, x, omega, n, next);
        std::mem::swap(x, next);
        // Residual norm = ||Ax - b||_∞.
        let mut max_resid = 0.0_f64;
        for i in 0..n_us {
            let row_dot: f64 = (0..n_us).map(|j| a[i * n_us + j] * x[j]).sum();
            let r = (row_dot - b[i]).abs();
            if r > max_resid {
                max_resid = r;
            }
        }
        if max_resid < tol {
            return iter + 1;
        }
    }
    max_iters
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-4 * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn identity_system_converges_to_b() {
        // A = I, b = [1, 2, 3] → solution = b.
        let a = vec![1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0];
        let b = vec![1.0, 2.0, 3.0];
        let x0 = vec![0.0; 3];
        let (x, iters) = solve_to_tolerance(&a, &b, &x0, 1.0, 3, 1e-6, 100);
        for (a, b) in x.iter().zip(b.iter()) {
            assert!(approx_eq(*a, *b));
        }
        assert!(iters <= 5, "identity converges in 1 step");
    }

    #[test]
    fn diagonally_dominant_system_converges() {
        // 2x2 system: 4x + y = 9, 2x + 5y = 8 → x=37/18 ≈ 2.0556, y=14/18 ≈ 0.7778.
        let a = vec![4.0, 1.0, 2.0, 5.0];
        let b = vec![9.0, 8.0];
        let x0 = vec![0.0, 0.0];
        let (x, _) = solve_to_tolerance(&a, &b, &x0, 0.66, 2, 1e-4, 1000);
        assert!(approx_eq(x[0], 37.0 / 18.0));
        assert!(approx_eq(x[1], 14.0 / 18.0));
    }

    #[test]
    fn zero_max_iters_returns_initial() {
        let a = vec![1.0, 0.0, 0.0, 1.0];
        let b = vec![5.0, 7.0];
        let x0 = vec![0.0, 0.0];
        let (x, iters) = solve_to_tolerance(&a, &b, &x0, 1.0, 2, 1e-6, 0);
        assert_eq!(x, x0);
        assert_eq!(iters, 0);
    }

    #[test]
    fn solve_to_tolerance_into_matches_owned_solver() {
        let a = vec![4.0, 1.0, 2.0, 5.0];
        let b = vec![9.0, 8.0];
        let x0 = vec![0.0, 0.0];
        let (owned, owned_iters) = solve_to_tolerance(&a, &b, &x0, 0.66, 2, 1e-4, 1000);
        let mut x = Vec::new();
        let mut next = Vec::new();
        let into_iters =
            solve_to_tolerance_into(&a, &b, &x0, 0.66, 2, 1e-4, 1000, &mut x, &mut next);
        assert_eq!(into_iters, owned_iters);
        assert_eq!(x.len(), owned.len());
        for (a, b) in x.iter().zip(owned.iter()) {
            assert!(approx_eq(*a, *b));
        }
    }

    #[test]
    fn matroid_solve_step_is_jacobi_iteration() {
        let a = vec![2.0, 0.0, 0.0, 2.0];
        let b = vec![6.0, 8.0];
        let x_in = vec![0.0, 0.0];
        let x_out = matroid_solve_step(&a, &b, &x_in, 1.0, 2);
        // Pure Jacobi step with x_in = 0 yields x_out = b/diag.
        assert!(approx_eq(x_out[0], 3.0));
        assert!(approx_eq(x_out[1], 4.0));
    }
}
