//! Quantum singular value transform (classical) — block-encoded matrix
//! function via Chebyshev polynomial of singular values (#34).
//!
//! QSVT (Gilyen-Su-Low-Wiebe 2018) gives a unified framework for
//! matrix functions: inverse, sqrt, exp, all without eigendecomposition.
//! The classical "dequantized" form (Tang 2019) computes
//! `f(A) · v` via:
//!
//! ```text
//!   f(A) · v ≈ Σ_k c_k T_k(A/||A||) · v
//! ```
//!
//! where `T_k` are Chebyshev polynomials of the first kind. Composes
//! with #5 chebyshev_filter (already on graph Laplacians) — same
//! recurrence, applied here to a generic matrix.
//!
//! This file ships the **block-encoding scaling step** primitive —
//! given matrix `A` and Frobenius norm `||A||`, produce the scaled
//! `A / ||A||` whose singular values lie in `[0, 1]`. Caller composes
//! with #5 chebyshev_filter and a coefficient buffer to evaluate
//! `f(A) · v` for any analytic `f`.
//!
//! # Why this primitive is dual-use
//!
//! | Consumer | Use |
//! |---|---|
//! | future `vyre-libs::math::matrix_function` | unified matrix-function family |
//! | future `vyre-libs::sci::quantum_sim` | classical simulation of quantum circuits |
//! | `vyre-foundation::transform` Wasserstein dispatch analysis | matrix-function evaluation (matrix log, exp) for transport-based fusion-cost analyses |

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Op id.
pub const OP_ID: &str = "vyre-primitives::math::qsvt_block_encode";

/// Emit `A_scaled[i, j] = A[i, j] / norm` for `n × n` matrix `A`.
///
/// The norm is supplied as a single-element u32 buffer in 16.16 fp;
/// caller precomputes (typically as Frobenius norm via reduce::sum
/// then sqrt). After scaling, `A_scaled` has spectral norm `≤ 1`, the
/// requirement for QSVT block encoding.
#[must_use]
pub fn qsvt_block_encode(a: &str, norm: &str, a_scaled: &str, n: u32) -> Program {
    if n == 0 {
        return crate::invalid_output_program(
            OP_ID,
            a_scaled,
            DataType::U32,
            format!("Fix: qsvt_block_encode requires n > 0, got {n}."),
        );
    }

    let cells = n * n;
    let t = Expr::InvocationId { axis: 0 };
    let n_v = Expr::load(norm, Expr::u32(0));
    let safe_norm = Expr::select(Expr::eq(n_v.clone(), Expr::u32(0)), Expr::u32(1), n_v);
    let value = Expr::div(
        Expr::shl(Expr::load(a, t.clone()), Expr::u32(16)),
        safe_norm,
    );

    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(cells)),
        vec![Node::store(a_scaled, t, value)],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(a, 0, BufferAccess::ReadOnly, DataType::U32).with_count(cells),
            BufferDecl::storage(norm, 1, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage(a_scaled, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(cells),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference: scale `A` by `1 / ||A||_F`.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn qsvt_block_encode_cpu(a: &[f64], n: u32) -> (Vec<f64>, f64) {
    let mut out = Vec::new();
    let frob = qsvt_block_encode_cpu_into(a, n, &mut out);
    (out, frob)
}

/// CPU reference: scale `A` by `1 / ||A||_F` using caller-owned output.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn qsvt_block_encode_cpu_into(a: &[f64], n: u32, out: &mut Vec<f64>) -> f64 {
    let n = n as usize;
    let frob: f64 = a.iter().map(|&v| v * v).sum::<f64>().sqrt();
    let safe = frob.max(1e-30);
    out.clear();
    out.reserve(n * n);
    out.extend((0..(n * n)).map(|idx| a.get(idx).copied().unwrap_or(0.0) / safe));
    frob
}

/// CPU reference: evaluate `f(A) · v` via Chebyshev expansion. `coeffs[k]`
/// is the k-th Chebyshev coefficient of `f` (caller computes via numerical
/// integration). Operates on already-scaled `A`.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn qsvt_apply_cpu(a_scaled: &[f64], v: &[f64], coeffs: &[f64], n: u32) -> Vec<f64> {
    let mut out = Vec::new();
    let mut t_prev = Vec::new();
    let mut t_curr = Vec::new();
    let mut t_next = Vec::new();
    qsvt_apply_cpu_into(
        a_scaled,
        v,
        coeffs,
        n,
        &mut out,
        &mut t_prev,
        &mut t_curr,
        &mut t_next,
    );
    out
}

/// CPU reference: evaluate `f(A) · v` using caller-owned recurrence buffers.
#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn qsvt_apply_cpu_into(
    a_scaled: &[f64],
    v: &[f64],
    coeffs: &[f64],
    n: u32,
    out: &mut Vec<f64>,
    t_prev: &mut Vec<f64>,
    t_curr: &mut Vec<f64>,
    t_next: &mut Vec<f64>,
) {
    let n = n as usize;
    let k_steps = coeffs.len();
    out.clear();
    if k_steps == 0 || a_scaled.len() != n * n || v.len() != n {
        t_prev.clear();
        t_curr.clear();
        t_next.clear();
        return;
    }

    // T_0(A) v = v
    // T_1(A) v = A v
    // T_{k+1}(A) v = 2 A T_k v - T_{k-1} v
    out.reserve(n);
    out.extend(v.iter().map(|&xi| coeffs[0] * xi));
    if k_steps == 1 {
        return;
    }

    t_prev.clear();
    t_prev.extend_from_slice(v);
    t_curr.clear();
    t_curr.resize(n, 0.0);
    mat_vec_into(a_scaled, t_prev, n, t_curr);
    for i in 0..n {
        out[i] += coeffs[1] * t_curr[i];
    }

    for &c_k in coeffs.iter().take(k_steps).skip(2) {
        t_next.clear();
        t_next.resize(n, 0.0);
        mat_vec_into(a_scaled, t_curr, n, t_next);
        for i in 0..n {
            t_next[i] = 2.0 * t_next[i] - t_prev[i];
        }
        for i in 0..n {
            out[i] += c_k * t_next[i];
        }
        std::mem::swap(t_prev, t_curr);
        std::mem::swap(t_curr, t_next);
    }
}

#[cfg(any(test, feature = "cpu-parity"))]
fn mat_vec_into(matrix: &[f64], vector: &[f64], n: usize, out: &mut [f64]) {
    for i in 0..n {
        let mut sum = 0.0;
        for j in 0..n {
            sum += matrix[i * n + j] * vector[j];
        }
        out[i] = sum;
    }
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || qsvt_block_encode("a", "norm", "a_scaled", 4),
        None,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-6 * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn cpu_block_encode_scales_correctly() {
        let a = vec![3.0, 0.0, 0.0, 4.0]; // ||A||_F = 5
        let (scaled, norm) = qsvt_block_encode_cpu(&a, 2);
        assert!(approx_eq(norm, 5.0));
        assert!(approx_eq(scaled[0], 0.6));
        assert!(approx_eq(scaled[3], 0.8));
    }

    #[test]
    fn cpu_block_encode_short_matrix_is_zero_padded() {
        let (scaled, norm) = qsvt_block_encode_cpu(&[2.0], 2);
        assert!(approx_eq(norm, 2.0));
        assert_eq!(scaled, vec![1.0, 0.0, 0.0, 0.0]);
    }

    #[test]
    fn cpu_qsvt_constant_function_passes() {
        // f(A) = c · I implemented as Chebyshev coeffs = [c]
        let a = vec![0.5, 0.0, 0.0, 0.5];
        let v = vec![1.0, 1.0];
        let out = qsvt_apply_cpu(&a, &v, &[3.0], 2);
        assert!(approx_eq(out[0], 3.0));
        assert!(approx_eq(out[1], 3.0));
    }

    #[test]
    fn cpu_qsvt_linear_function_recovers_av() {
        // f(A) = A → coeffs = [0, 1]; f(A) v = A v.
        let a = vec![0.5, 0.5, 0.5, 0.5];
        let v = vec![1.0, 0.0];
        let out = qsvt_apply_cpu(&a, &v, &[0.0, 1.0], 2);
        // A v = (0.5, 0.5)
        assert!(approx_eq(out[0], 0.5));
        assert!(approx_eq(out[1], 0.5));
    }

    #[test]
    fn cpu_qsvt_into_reuses_buffers() {
        let a = vec![0.5, 0.5, 0.5, 0.5];
        let v = vec![1.0, 0.0];
        let mut out = Vec::with_capacity(8);
        let mut prev = Vec::with_capacity(8);
        let mut curr = Vec::with_capacity(8);
        let mut next = Vec::with_capacity(8);
        let pointers = [out.as_ptr(), prev.as_ptr(), curr.as_ptr(), next.as_ptr()];
        qsvt_apply_cpu_into(
            &a,
            &v,
            &[0.0, 1.0],
            2,
            &mut out,
            &mut prev,
            &mut curr,
            &mut next,
        );
        assert!(approx_eq(out[0], 0.5));
        assert!(approx_eq(out[1], 0.5));
        for ptr in [out.as_ptr(), prev.as_ptr(), curr.as_ptr(), next.as_ptr()] {
            assert!(pointers.contains(&ptr));
        }
    }

    #[test]
    fn cpu_qsvt_zero_signal_zero_output() {
        let a = vec![1.0, 0.0, 0.0, 1.0];
        let v = vec![0.0; 2];
        let out = qsvt_apply_cpu(&a, &v, &[1.0, 0.5, 0.25], 2);
        assert!(approx_eq(out[0], 0.0));
        assert!(approx_eq(out[1], 0.0));
    }

    #[test]
    fn ir_program_buffer_layout() {
        let p = qsvt_block_encode("A", "n", "As", 4);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        assert_eq!(p.buffers[0].count(), 16);
        assert_eq!(p.buffers[1].count(), 1);
        assert_eq!(p.buffers[2].count(), 16);
    }

    #[test]
    fn zero_n_traps() {
        let p = qsvt_block_encode("A", "n", "As", 0);
        assert!(p.stats().trap());
    }
}
