//! Fractional-calculus kernel — Caputo derivative + Riemann-Liouville
//! derivative as a 1D discrete convolution kernel.
//!
//! Fractional derivatives `D^α f(x)` for non-integer α generalize
//! `d/dx` to arbitrary order. Their discrete Grünwald-Letnikov form
//! is a 1D convolution against a specific weight kernel:
//!
//! ```text
//!   D^α f[n] ≈ h^{-α} · Σ_{k=0..n} w_k^α · f[n-k]
//!
//!   w_0^α = 1
//!   w_k^α = (1 - (α+1)/k) · w_{k-1}^α
//! ```
//!
//! That's exactly the shape of [`crate::math::conv1d`] with a kernel
//! of length `n` and stride 1. This file ships only the **kernel
//! generator** as a host-side helper; the GPU dispatch composes
//! [`crate::math::conv1d`] with the precomputed kernel.
//!
//! # Why this primitive is dual-use
//!
//! | Consumer | Use |
//! |---|---|
//! | future `vyre-libs::physics::diffusion` | anomalous-diffusion solvers (sub-/super-diffusion) |
//! | future `vyre-libs::nn::fractional` | fractional gradient descent + FractalNet variants |
//! | future `vyre-libs::signal::fractional` | viscoelastic-material control + audio processing |
//!
//! Self-consumer is weak (no obvious vyre-internal use of fractional
//! calculus). The lego rule still passes on user-dialect coverage.
//!
//! # Lego-rule note
//!
//! No new GPU primitive ships. The Grünwald-Letnikov weights are a
//! **kernel data table** that vyre-primitives::math::conv1d already
//! consumes. The single new function is the host-side
//! [`crate::math::fractional::grunwald_letnikov_kernel`] that produces the weights.

/// Generate the Grünwald-Letnikov weight kernel of length `n` for
/// fractional order `alpha`. Output `w[k]` such that
/// `D^α f[i] ≈ h^{-α} · Σ_k w[k] · f[i-k]`.
///
/// `alpha = 1.0` recovers the standard backward-difference
/// approximation of the first derivative; `alpha = 2.0` recovers the
/// standard backward-difference of the second derivative; non-integer
/// values give the genuine fractional kernel.
#[must_use]
pub fn grunwald_letnikov_kernel(alpha: f64, n: u32) -> Vec<f64> {
    let mut out = Vec::new();
    grunwald_letnikov_kernel_into(alpha, n, &mut out);
    out
}

/// Generate the Grünwald-Letnikov kernel into caller-owned storage.
pub fn grunwald_letnikov_kernel_into(alpha: f64, n: u32, out: &mut Vec<f64>) {
    out.clear();
    if n == 0 || !alpha.is_finite() {
        return;
    }
    out.resize(n as usize, 0.0);
    out[0] = 1.0;
    for k in 1..n as usize {
        // w_k = (1 - (alpha + 1) / k) · w_{k-1}
        out[k] = (1.0 - (alpha + 1.0) / (k as f64)) * out[k - 1];
    }
}

/// Convert a Grünwald-Letnikov kernel into the 16.16 fixed-point
/// representation that [`crate::math::conv1d`] consumes.
#[must_use]
pub fn kernel_to_fixed_16_16(kernel: &[f64], step: f64, alpha: f64) -> Vec<u32> {
    let mut out = Vec::new();
    kernel_to_fixed_16_16_into(kernel, step, alpha, &mut out);
    out
}

/// Convert a Grünwald-Letnikov kernel into 16.16 fixed point in caller-owned storage.
pub fn kernel_to_fixed_16_16_into(kernel: &[f64], step: f64, alpha: f64, out: &mut Vec<u32>) {
    out.clear();
    if step <= 0.0 || !step.is_finite() || !alpha.is_finite() {
        return;
    }
    let scale = step.powf(-alpha);
    out.reserve(kernel.len());
    for &w in kernel {
        let scaled = w * scale * 65536.0;
        // Wrap negative values into u32 two's-complement so
        // subsequent fixed-point multiplies preserve sign on
        // 32-bit modular arithmetic.
        out.push(scaled.round() as i64 as u32);
    }
}

/// CPU reference: apply a length-`n` GL kernel to a signal `f` of
/// length `m`. Uses zero-padding for `i - k < 0`.
#[must_use]
pub fn fractional_derivative_cpu(f: &[f64], alpha: f64, step: f64) -> Vec<f64> {
    let mut kernel = Vec::new();
    let mut out = Vec::new();
    fractional_derivative_cpu_into(f, alpha, step, &mut kernel, &mut out);
    out
}

/// CPU reference into caller-owned kernel and output storage.
pub fn fractional_derivative_cpu_into(
    f: &[f64],
    alpha: f64,
    step: f64,
    kernel: &mut Vec<f64>,
    out: &mut Vec<f64>,
) {
    out.clear();
    if step <= 0.0 || !step.is_finite() || !alpha.is_finite() {
        kernel.clear();
        return;
    }
    let n = f.len();
    grunwald_letnikov_kernel_into(alpha, n as u32, kernel);
    if kernel.len() != n {
        return;
    }
    let scale = step.powf(-alpha);

    out.reserve(n);
    for i in 0..n {
        let mut acc = 0.0;
        for k in 0..=i {
            acc += kernel[k] * f[i - k];
        }
        out.push(acc * scale);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f64 = 1e-10;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < EPS * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn alpha_1_recovers_backward_difference() {
        // GL weights for α=1: 1, -1, 0, 0, …
        let w = grunwald_letnikov_kernel(1.0, 5);
        assert!(approx_eq(w[0], 1.0));
        assert!(approx_eq(w[1], -1.0));
        // Higher orders should be zero (or extremely small)
        for &v in &w[2..] {
            assert!(v.abs() < EPS);
        }
    }

    #[test]
    fn alpha_2_recovers_second_difference() {
        // GL weights for α=2: 1, -2, 1, 0, …
        let w = grunwald_letnikov_kernel(2.0, 5);
        assert!(approx_eq(w[0], 1.0));
        assert!(approx_eq(w[1], -2.0));
        assert!(approx_eq(w[2], 1.0));
        for &v in &w[3..] {
            assert!(v.abs() < EPS);
        }
    }

    #[test]
    fn alpha_zero_recovers_identity() {
        // GL weights for α=0: 1, 0, 0, … (identity).
        let w = grunwald_letnikov_kernel(0.0, 4);
        assert!(approx_eq(w[0], 1.0));
        for &v in &w[1..] {
            assert!(v.abs() < EPS);
        }
    }

    #[test]
    fn fractional_alpha_half_kernel_is_long_tailed() {
        // For non-integer α (α=0.5), the kernel does NOT terminate.
        // All weights should be nonzero.
        let w = grunwald_letnikov_kernel(0.5, 8);
        for (i, &v) in w.iter().enumerate() {
            assert!(v.abs() > 1e-12, "weight {i} unexpectedly zero: {v}");
        }
    }

    #[test]
    fn cpu_first_derivative_constant_signal_is_zero() {
        // d/dx of a constant is 0 (apart from edge effect at i=0).
        let f = vec![3.0; 5];
        let d = fractional_derivative_cpu(&f, 1.0, 1.0);
        // i=0: 1·f[0] = 3. i≥1: 1·f[i] - 1·f[i-1] = 0.
        assert!(approx_eq(d[0], 3.0));
        for v in &d[1..] {
            assert!(approx_eq(*v, 0.0));
        }
    }

    #[test]
    fn cpu_first_derivative_linear_signal_is_constant() {
        // f(i) = i. d/dx ≈ 1 (apart from i=0 edge).
        let f: Vec<f64> = (0..6).map(|i| i as f64).collect();
        let d = fractional_derivative_cpu(&f, 1.0, 1.0);
        for v in &d[1..] {
            assert!(approx_eq(*v, 1.0));
        }
    }

    #[test]
    fn fixed_point_conversion_preserves_sign() {
        let kernel = vec![1.0, -0.5];
        let fp = kernel_to_fixed_16_16(&kernel, 1.0, 1.0);
        assert_eq!(fp[0], 65536); // 1.0 in 16.16
        assert_eq!(fp[1] as i32, -32768); // -0.5 in 16.16, two's comp
    }

    #[test]
    fn cpu_into_reuses_fractional_buffers() {
        let f: Vec<f64> = (0..6).map(|i| i as f64).collect();
        let expected = fractional_derivative_cpu(&f, 1.0, 1.0);
        let mut kernel = Vec::with_capacity(f.len());
        let mut out = Vec::with_capacity(f.len());
        let mut fixed = Vec::with_capacity(f.len());

        fractional_derivative_cpu_into(&f, 1.0, 1.0, &mut kernel, &mut out);
        kernel_to_fixed_16_16_into(&kernel, 1.0, 1.0, &mut fixed);
        let kernel_ptr = kernel.as_ptr();
        let out_ptr = out.as_ptr();
        let fixed_ptr = fixed.as_ptr();
        fractional_derivative_cpu_into(&f, 1.0, 1.0, &mut kernel, &mut out);
        kernel_to_fixed_16_16_into(&kernel, 1.0, 1.0, &mut fixed);

        assert_eq!(out, expected);
        assert_eq!(kernel.as_ptr(), kernel_ptr);
        assert_eq!(out.as_ptr(), out_ptr);
        assert_eq!(fixed.as_ptr(), fixed_ptr);
    }

    #[test]
    fn zero_n_returns_empty_kernel() {
        assert!(grunwald_letnikov_kernel(0.5, 0).is_empty());
    }
}
