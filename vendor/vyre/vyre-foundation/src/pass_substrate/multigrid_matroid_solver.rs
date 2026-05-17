//! Multigrid-style smoothing step used by matroid fusion relaxations.

use crate::cpu_references::jacobi_smooth_step_cpu;

/// Run one weighted Jacobi smoothing step for the dense relaxation system.
#[must_use]
pub fn matroid_solve_step(a: &[f64], b: &[f64], x: &[f64], weight: f64, n: u32) -> Vec<f64> {
    jacobi_smooth_step_cpu(a, b, x, weight, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_system_one_step_converges() {
        // A = I₃, b = [1,2,3], x = [0,0,0], w = 1.0.
        // One step: x_new = b (since A is identity).
        let a = vec![1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0];
        let b = vec![1.0, 2.0, 3.0];
        let x = vec![0.0, 0.0, 0.0];
        let result = matroid_solve_step(&a, &b, &x, 1.0, 3);
        assert!((result[0] - 1.0).abs() < 1e-12);
        assert!((result[1] - 2.0).abs() < 1e-12);
        assert!((result[2] - 3.0).abs() < 1e-12);
    }

    #[test]
    fn zero_weight_preserves_state() {
        let a = vec![2.0, 0.0, 0.0, 2.0];
        let b = vec![10.0, 20.0];
        let x = vec![5.0, 7.0];
        let result = matroid_solve_step(&a, &b, &x, 0.0, 2);
        assert_eq!(result, vec![5.0, 7.0]);
    }

    #[test]
    fn partial_weight_moves_toward_solution() {
        // A = I₂, b = [10, 20], x = [0, 0], w = 0.5.
        // x_new = 0 + 0.5 * (b - 0) / 1.0 = [5, 10].
        let a = vec![1.0, 0.0, 0.0, 1.0];
        let b = vec![10.0, 20.0];
        let x = vec![0.0, 0.0];
        let result = matroid_solve_step(&a, &b, &x, 0.5, 2);
        assert!((result[0] - 5.0).abs() < 1e-12);
        assert!((result[1] - 10.0).abs() < 1e-12);
    }
}
