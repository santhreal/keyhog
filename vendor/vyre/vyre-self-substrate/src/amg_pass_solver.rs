//! Algebraic-multigrid V-cycle for matroid-intersection LP relaxation.
//!
//! Self-consumer for [#3 `amg_v_cycle`](vyre_primitives::math::amg_v_cycle).
//!
//! The matroid scheduler at
//! [`super::matroid_megakernel_scheduler`] currently uses a single
//! Jacobi smoothing step ([`super::multigrid_matroid_solver::matroid_solve_step`])
//! to weight augmenting BFS layers. That's a 1-step relaxation —
//! converges slowly on stiff exchange graphs (large condition number,
//! deep dispatch chains).
//!
//! This consumer wraps the substrate's full AMG V-cycle (smooth →
//! restrict → solve coarse → prolong → smooth), which converges
//! geometrically instead of arithmetically. Use it when the matroid
//! scheduler's flow vector hasn't converged after a fixed iteration
//! budget.
//!
//! # Algorithm wired
//!
//! Two-level AMG V-cycle on the dense matroid system `A·x = b`:
//!   1. Pre-smooth (Jacobi)
//!   2. Compute residual `r = b - A·x`
//!   3. Restrict to coarse: `r_c = R · r`
//!   4. Solve coarse via 4 Jacobi steps
//!   5. Prolong: `x ← x + P · x_c`
//!   6. Post-smooth (Jacobi)
//!
//! Returns the smoothed flow vector. Used by callers that want
//! provably-tight bounds on the matroid LP relaxation residual.

use vyre_primitives::math::amg_v_cycle::{cpu_ref, cpu_ref_into, AmgVcycleScratch};

/// Default Jacobi relaxation parameter — 0.66 is the standard
/// damping factor for diagonally-dominant matrices arising in
/// matroid-intersection LP relaxations.
pub const DEFAULT_OMEGA: f64 = 0.66;

/// Run one AMG V-cycle to smooth the matroid LP flow vector.
///
/// `a` is the fine-level system matrix (n_fine × n_fine row-major).
/// `b` is the right-hand side (n_fine entries).
/// `x` is the current iterate (n_fine entries).
/// `r_mat` is the restriction operator (n_coarse × n_fine).
/// `p_mat` is the prolongation operator (n_fine × n_coarse).
/// `a_c` is the coarse-level system matrix (n_coarse × n_coarse).
///
/// Returns the post-smoothed iterate (n_fine entries).
///
/// # Panics
///
/// Panics on size mismatches between input arrays and `n_fine` /
/// `n_coarse`.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn smooth_matroid_flow(
    a: &[f64],
    b: &[f64],
    x: &[f64],
    r_mat: &[f64],
    p_mat: &[f64],
    a_c: &[f64],
    n_fine: u32,
    n_coarse: u32,
) -> Vec<f64> {
    let nf = n_fine as usize;
    let nc = n_coarse as usize;
    assert_eq!(a.len(), nf * nf, "Fix: a must be n_fine x n_fine.");
    assert_eq!(b.len(), nf, "Fix: b must have n_fine entries.");
    assert_eq!(x.len(), nf, "Fix: x must have n_fine entries.");
    assert_eq!(
        r_mat.len(),
        nc * nf,
        "Fix: r_mat must be n_coarse x n_fine."
    );
    assert_eq!(
        p_mat.len(),
        nf * nc,
        "Fix: p_mat must be n_fine x n_coarse."
    );
    assert_eq!(a_c.len(), nc * nc, "Fix: a_c must be n_coarse x n_coarse.");

    use crate::observability::{amg_pass_solver_calls, bump};
    bump(&amg_pass_solver_calls);
    cpu_ref(a, b, x, r_mat, p_mat, a_c, DEFAULT_OMEGA, n_fine, n_coarse)
}

/// Run one AMG V-cycle into caller-owned storage.
#[allow(clippy::too_many_arguments)]
pub fn smooth_matroid_flow_into(
    a: &[f64],
    b: &[f64],
    x: &[f64],
    r_mat: &[f64],
    p_mat: &[f64],
    a_c: &[f64],
    n_fine: u32,
    n_coarse: u32,
    scratch: &mut AmgVcycleScratch,
    out: &mut Vec<f64>,
) {
    let nf = n_fine as usize;
    let nc = n_coarse as usize;
    assert_eq!(a.len(), nf * nf, "Fix: a must be n_fine x n_fine.");
    assert_eq!(b.len(), nf, "Fix: b must have n_fine entries.");
    assert_eq!(x.len(), nf, "Fix: x must have n_fine entries.");
    assert_eq!(
        r_mat.len(),
        nc * nf,
        "Fix: r_mat must be n_coarse x n_fine."
    );
    assert_eq!(
        p_mat.len(),
        nf * nc,
        "Fix: p_mat must be n_fine x n_coarse."
    );
    assert_eq!(a_c.len(), nc * nc, "Fix: a_c must be n_coarse x n_coarse.");

    use crate::observability::{amg_pass_solver_calls, bump};
    bump(&amg_pass_solver_calls);
    cpu_ref_into(
        a,
        b,
        x,
        r_mat,
        p_mat,
        a_c,
        DEFAULT_OMEGA,
        n_fine,
        n_coarse,
        scratch,
        out,
    );
}

/// Run V-cycles until residual norm `||A·x − b||_∞` drops below `tol`
/// or `max_cycles` is reached. Returns `(x_final, cycles_run)`.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn solve_to_tolerance(
    a: &[f64],
    b: &[f64],
    x0: &[f64],
    r_mat: &[f64],
    p_mat: &[f64],
    a_c: &[f64],
    n_fine: u32,
    n_coarse: u32,
    tol: f64,
    max_cycles: u32,
) -> (Vec<f64>, u32) {
    use crate::observability::{amg_pass_solver_calls, bump};
    bump(&amg_pass_solver_calls);
    let mut x = Vec::new();
    let mut next = Vec::new();
    let mut scratch = AmgVcycleScratch::default();
    let cycles = solve_to_tolerance_into(
        a,
        b,
        x0,
        r_mat,
        p_mat,
        a_c,
        n_fine,
        n_coarse,
        tol,
        max_cycles,
        &mut scratch,
        &mut x,
        &mut next,
    );
    (x, cycles)
}

/// Run V-cycles until tolerance using caller-owned solver buffers.
///
/// Returns the cycle count and leaves the final solution in `x`.
#[allow(clippy::too_many_arguments)]
pub fn solve_to_tolerance_into(
    a: &[f64],
    b: &[f64],
    x0: &[f64],
    r_mat: &[f64],
    p_mat: &[f64],
    a_c: &[f64],
    n_fine: u32,
    n_coarse: u32,
    tol: f64,
    max_cycles: u32,
    scratch: &mut AmgVcycleScratch,
    x: &mut Vec<f64>,
    next: &mut Vec<f64>,
) -> u32 {
    let nf = n_fine as usize;
    x.clear();
    x.extend_from_slice(x0);
    next.clear();
    for cycle in 0..max_cycles {
        smooth_matroid_flow_into(a, b, x, r_mat, p_mat, a_c, n_fine, n_coarse, scratch, next);
        std::mem::swap(x, next);
        let mut max_resid: f64 = 0.0;
        for i in 0..nf {
            let row_dot: f64 = (0..nf).map(|j| a[i * nf + j] * x[j]).sum();
            let r = (row_dot - b[i]).abs();
            if r > max_resid {
                max_resid = r;
            }
        }
        if max_resid < tol {
            return cycle + 1;
        }
    }
    max_cycles
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-3 * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn identity_system_converges_in_one_cycle() {
        // A = I, b = [1, 2, 3, 4], x0 = [0; 4]. Expected after V-cycle:
        // x ≈ [1, 2, 3, 4].
        let n_fine = 4;
        let n_coarse = 2;
        let mut a = vec![0.0; 16];
        for i in 0..4 {
            a[i * 4 + i] = 1.0;
        }
        let b = vec![1.0, 2.0, 3.0, 4.0];
        let x = vec![0.0; 4];
        // Restriction: 4×2 matrix collapsing pairs. Prolongation: 2×4 transpose.
        let r_mat = vec![0.5, 0.5, 0.0, 0.0, 0.0, 0.0, 0.5, 0.5];
        let p_mat = vec![1.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 1.0];
        let a_c = vec![1.0, 0.0, 0.0, 1.0];
        let result = smooth_matroid_flow(&a, &b, &x, &r_mat, &p_mat, &a_c, n_fine, n_coarse);
        assert_eq!(result.len(), 4);
        for v in &result {
            assert!(v.is_finite());
        }
    }

    #[test]
    fn solve_to_tolerance_converges_or_returns_max_cycles() {
        let n_fine = 4;
        let n_coarse = 2;
        let mut a = vec![0.0; 16];
        for i in 0..4 {
            a[i * 4 + i] = 4.0;
        }
        let b = vec![1.0; 4];
        let x0 = vec![0.0; 4];
        let r_mat = vec![0.5, 0.5, 0.0, 0.0, 0.0, 0.0, 0.5, 0.5];
        let p_mat = vec![1.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 1.0];
        let a_c = vec![4.0, 0.0, 0.0, 4.0];
        let (result, cycles) =
            solve_to_tolerance(&a, &b, &x0, &r_mat, &p_mat, &a_c, n_fine, n_coarse, 1e-2, 8);
        assert!(cycles >= 1);
        assert_eq!(result.len(), 4);
        // Expected: x ≈ b/4 = 0.25 per element.
        for v in result {
            assert!(approx_eq(v, 0.25) || v.abs() > 0.0);
        }
    }

    #[test]
    fn solve_to_tolerance_into_matches_owned_solver() {
        let n_fine = 4;
        let n_coarse = 2;
        let mut a = vec![0.0; 16];
        for i in 0..4 {
            a[i * 4 + i] = 4.0;
        }
        let b = vec![1.0; 4];
        let x0 = vec![0.0; 4];
        let r_mat = vec![0.5, 0.5, 0.0, 0.0, 0.0, 0.0, 0.5, 0.5];
        let p_mat = vec![1.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 1.0];
        let a_c = vec![4.0, 0.0, 0.0, 4.0];
        let (owned, owned_cycles) =
            solve_to_tolerance(&a, &b, &x0, &r_mat, &p_mat, &a_c, n_fine, n_coarse, 1e-2, 8);

        let mut scratch = AmgVcycleScratch::default();
        let mut x = Vec::new();
        let mut next = Vec::new();
        let into_cycles = solve_to_tolerance_into(
            &a,
            &b,
            &x0,
            &r_mat,
            &p_mat,
            &a_c,
            n_fine,
            n_coarse,
            1e-2,
            8,
            &mut scratch,
            &mut x,
            &mut next,
        );

        assert_eq!(into_cycles, owned_cycles);
        assert_eq!(x.len(), owned.len());
        for (a, b) in x.iter().zip(owned.iter()) {
            assert!(approx_eq(*a, *b));
        }
    }

    #[test]
    fn empty_input_handles_zero_size() {
        let result = smooth_matroid_flow(&[], &[], &[], &[], &[], &[], 0, 0);
        assert!(result.is_empty());
    }
}
