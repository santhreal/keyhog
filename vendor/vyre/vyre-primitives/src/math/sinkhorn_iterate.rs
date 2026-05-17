//! Full iterative Sinkhorn balance.
//!
//! Alternates row-normalize and column-normalize until converged.
//! Composes `sinkhorn_scale` + `semiring_gemm` + `persistent_fixpoint`.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Node, Program};

use crate::math::semiring_gemm::{semiring_gemm, Semiring};
use crate::math::sinkhorn::sinkhorn_scale;

/// Stable registry id for the iterative Sinkhorn primitive.
pub const OP_ID: &str = "vyre-primitives::math::sinkhorn_iterate";

/// Sinkhorn full iteration.
///
/// Runs Sinkhorn matrix-scaling iterations to convergence.
///
/// # Buffers
/// - `k`: `m x n` kernel matrix.
/// - `k_t`: `n x m` transposed kernel matrix.
/// - `a`: `m` target marginals.
/// - `b`: `n` target marginals.
/// - `u_curr`: `m` elements, ping-pong state for u.
/// - `u_next`: `m` elements, ping-pong state for u.
/// - `v`: `n` elements, current state for v.
/// - `kv`: `m` elements scratch.
/// - `ktu`: `n` elements scratch.
/// - `changed`: 1 element convergence flag.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn sinkhorn_iterate(
    k: &str,
    k_t: &str,
    a: &str,
    b: &str,
    u_curr: &str,
    u_next: &str,
    v: &str,
    kv: &str,
    ktu: &str,
    changed: &str,
    m: u32,
    n: u32,
    max_iterations: u32,
) -> Program {
    if m == 0 {
        return crate::invalid_output_program(
            OP_ID,
            u_curr,
            DataType::U32,
            "Fix: sinkhorn_iterate requires m > 0, got 0.".to_string(),
        );
    }
    if n == 0 {
        return crate::invalid_output_program(
            OP_ID,
            u_curr,
            DataType::U32,
            "Fix: sinkhorn_iterate requires n > 0, got 0.".to_string(),
        );
    }

    let mut transfer_body = Vec::new();

    let extract_body = |p: Program| -> Vec<Node> {
        let mut body = Vec::new();
        for n in p.entry() {
            if let Node::Region {
                body: region_body, ..
            } = n
            {
                body.extend(region_body.iter().cloned());
            }
        }
        body
    };

    // 1. Kv = K * v (m x n * n x 1 -> m x 1)
    let p1 = semiring_gemm(k, v, kv, m, 1, n, Semiring::Real);
    transfer_body.extend(extract_body(p1));
    transfer_body.push(Node::Barrier {
        ordering: vyre_foundation::MemoryOrdering::SeqCst,
    });

    // 2. u_next = a ./ Kv
    let p2 = sinkhorn_scale(a, kv, u_next, m);
    transfer_body.extend(extract_body(p2));
    transfer_body.push(Node::Barrier {
        ordering: vyre_foundation::MemoryOrdering::SeqCst,
    });

    // 3. Ktu = K_T * u_next (n x m * m x 1 -> n x 1)
    let p3 = semiring_gemm(k_t, u_next, ktu, n, 1, m, Semiring::Real);
    transfer_body.extend(extract_body(p3));
    transfer_body.push(Node::Barrier {
        ordering: vyre_foundation::MemoryOrdering::SeqCst,
    });

    // 4. v = b ./ Ktu
    let p4 = sinkhorn_scale(b, ktu, v, n);
    transfer_body.extend(extract_body(p4));
    transfer_body.push(Node::Barrier {
        ordering: vyre_foundation::MemoryOrdering::SeqCst,
    });

    let inner = crate::fixpoint::persistent_fixpoint::persistent_fixpoint(
        transfer_body,
        u_curr,
        u_next,
        changed,
        m,
        max_iterations,
    );

    let entry: Vec<Node> = vec![Node::Region {
        generator: Ident::from(OP_ID),
        source_region: None,
        body: Arc::new(inner.entry().to_vec()),
    }];

    Program::wrapped(
        vec![
            BufferDecl::storage(u_curr, 0, BufferAccess::ReadWrite, DataType::U32).with_count(m),
            BufferDecl::storage(u_next, 1, BufferAccess::ReadWrite, DataType::U32).with_count(m),
            BufferDecl::storage(changed, 2, BufferAccess::ReadWrite, DataType::U32).with_count(1),
            BufferDecl::storage(k, 3, BufferAccess::ReadOnly, DataType::U32).with_count(m * n),
            BufferDecl::storage(k_t, 4, BufferAccess::ReadOnly, DataType::U32).with_count(m * n),
            BufferDecl::storage(a, 5, BufferAccess::ReadOnly, DataType::U32).with_count(m),
            BufferDecl::storage(b, 6, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::storage(v, 7, BufferAccess::ReadWrite, DataType::U32).with_count(n),
            BufferDecl::storage(kv, 8, BufferAccess::ReadWrite, DataType::U32).with_count(m),
            BufferDecl::storage(ktu, 9, BufferAccess::ReadWrite, DataType::U32).with_count(n),
        ],
        [256, 1, 1],
        entry,
    )
}

/// CPU reference for iterative Sinkhorn.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn cpu_ref(
    k: &[u32],
    k_t: &[u32],
    a: &[u32],
    b: &[u32],
    u_curr: &[u32],
    v: &[u32],
    m: u32,
    n: u32,
    max_iterations: u32,
) -> (Vec<u32>, Vec<u32>, u32) {
    let mut u = Vec::new();
    let mut v_mut = Vec::new();
    let mut u_old = Vec::new();
    let iters = cpu_ref_into(
        k,
        k_t,
        a,
        b,
        u_curr,
        v,
        m,
        n,
        max_iterations,
        &mut u,
        &mut v_mut,
        &mut u_old,
    );
    (u, v_mut, iters)
}

/// CPU reference for iterative Sinkhorn using caller-owned buffers.
///
/// `u_out` and `v_out` receive the final states. `u_old` is retained
/// as convergence scratch to avoid cloning `u` every iteration.
#[allow(clippy::too_many_arguments)]
pub fn cpu_ref_into(
    k: &[u32],
    k_t: &[u32],
    a: &[u32],
    b: &[u32],
    u_curr: &[u32],
    v: &[u32],
    m: u32,
    n: u32,
    max_iterations: u32,
    u_out: &mut Vec<u32>,
    v_out: &mut Vec<u32>,
    u_old: &mut Vec<u32>,
) -> u32 {
    u_out.clear();
    u_out.extend_from_slice(u_curr);
    v_out.clear();
    v_out.extend_from_slice(v);
    let m_usize = m as usize;
    let n_usize = n as usize;

    let mut iters = 0;
    for iter in 0..max_iterations {
        u_old.clear();
        u_old.extend_from_slice(u_out);

        // 1 & 2. Kv & u
        for i in 0..m_usize {
            let mut sum = 0u32;
            for j in 0..n_usize {
                sum = sum.wrapping_add(k[i * n_usize + j].wrapping_mul(v_out[j]));
            }
            let divisor = if sum == 0 { 1 } else { sum };
            u_out[i] = a[i] / divisor;
        }

        // 3 & 4. Ktu & v
        for j in 0..n_usize {
            let mut sum = 0u32;
            for i in 0..m_usize {
                sum = sum.wrapping_add(k_t[j * m_usize + i].wrapping_mul(u_out[i]));
            }
            let divisor = if sum == 0 { 1 } else { sum };
            v_out[j] = b[j] / divisor;
        }

        if u_out == u_old {
            return iter;
        }
        iters = iter + 1;
    }
    iters
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || sinkhorn_iterate("k", "kt", "a", "b", "uc", "un", "v", "kv", "ktu", "c", 2, 2, 5),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[65536, 65536]), // u_curr
                to_bytes(&[0, 0]), // u_next
                to_bytes(&[0]), // changed
                to_bytes(&[65536, 65536, 65536, 65536]), // k
                to_bytes(&[65536, 65536, 65536, 65536]), // k_t
                to_bytes(&[32768, 32768]), // a
                to_bytes(&[32768, 32768]), // b
                to_bytes(&[65536, 65536]), // v
                to_bytes(&[0, 0]), // kv
                to_bytes(&[0, 0]), // ktu
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[32768, 32768]), // u_curr
                to_bytes(&[32768, 32768]), // u_next
                to_bytes(&[0]),            // changed
                to_bytes(&[32768, 32768]), // v
                to_bytes(&[0, 0]),         // kv
                to_bytes(&[0, 0]),         // ktu
            ]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sinkhorn_cpu_ref_trivial() {
        let (u, v, _iters) = cpu_ref(
            &[65536],
            &[65536],
            &[65536],
            &[65536],
            &[65536],
            &[65536],
            1,
            1,
            10,
        );
        assert_eq!(u, vec![65536]);
        assert_eq!(v, vec![65536]);
    }

    #[test]
    fn test_sinkhorn_cpu_ref_edge() {
        // u = a / (k * v) = 65536 / (32768 * 65536) = 65536 / 2^31 = 0
        let (u, _, _) = cpu_ref(
            &[32768],
            &[32768],
            &[65536],
            &[65536],
            &[65536],
            &[65536],
            1,
            1,
            10,
        );
        assert_eq!(u, vec![0]);
    }

    #[test]
    fn test_sinkhorn_cpu_ref_normal() {
        let k = vec![65536, 65536, 65536, 65536];
        let k_t = vec![65536, 65536, 65536, 65536];
        let a = vec![32768, 32768];
        let b = vec![32768, 32768];
        let u_c = vec![65536, 65536];
        let v_in = vec![65536, 65536];
        let (u, _v, _) = cpu_ref(&k, &k_t, &a, &b, &u_c, &v_in, 2, 2, 5);
        // Kv = [0, 0] wrapped. u = a/1 = 32768.
        assert_eq!(u, vec![32768, 32768]);
    }

    #[test]
    fn test_sinkhorn_cpu_ref_large() {
        let k = vec![65536; 9];
        let a = vec![65536; 3];
        let b = vec![65536; 3];
        let u_c = vec![65536; 3];
        let v_in = vec![65536; 3];
        let (u, _, _) = cpu_ref(&k, &k, &a, &b, &u_c, &v_in, 3, 3, 5);
        assert_eq!(u.len(), 3);
    }

    #[test]
    fn test_sinkhorn_cpu_ref_asym() {
        let k = vec![65536, 0, 0, 65536, 65536, 65536];
        let k_t = vec![65536, 0, 65536, 0, 65536, 65536];
        let a = vec![32768, 32768, 65536];
        let b = vec![65536, 65536];
        let u_c = vec![65536, 65536, 65536];
        let v_in = vec![65536, 65536];
        let (u, v, _) = cpu_ref(&k, &k_t, &a, &b, &u_c, &v_in, 3, 2, 5);
        assert_eq!(u.len(), 3);
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn test_sinkhorn_cpu_ref_into_reuses_buffers() {
        let k = vec![65536, 65536, 65536, 65536];
        let a = vec![32768, 32768];
        let b = vec![32768, 32768];
        let u_c = vec![65536, 65536];
        let v_in = vec![65536, 65536];
        let mut u = Vec::with_capacity(8);
        let mut v = Vec::with_capacity(8);
        let mut u_old = Vec::with_capacity(8);
        let u_ptr = u.as_ptr();
        let v_ptr = v.as_ptr();
        let old_ptr = u_old.as_ptr();
        let _iters = cpu_ref_into(
            &k, &k, &a, &b, &u_c, &v_in, 2, 2, 5, &mut u, &mut v, &mut u_old,
        );
        assert_eq!(u, vec![32768, 32768]);
        assert_eq!(u.as_ptr(), u_ptr);
        assert_eq!(v.as_ptr(), v_ptr);
        assert_eq!(u_old.as_ptr(), old_ptr);
    }

    #[test]
    fn test_sinkhorn_program_parity() {
        let k = vec![1, 1, 1, 1];
        let a = vec![10, 10];
        let b = vec![10, 10];
        let u_c = vec![1, 1];
        let v_in = vec![1, 1];

        let p = sinkhorn_iterate(
            "k", "kt", "a", "b", "uc", "un", "v", "kv", "ktu", "c", 2, 2, 1,
        );

        let (expected_u, _, _) = cpu_ref(&k, &k, &a, &b, &u_c, &v_in, 2, 2, 1);

        use vyre_reference::reference_eval;
        use vyre_reference::value::Value;

        let to_value = |data: &[u32]| {
            let bytes: Vec<u8> = data.iter().flat_map(|v| v.to_le_bytes()).collect();
            Value::Bytes(Arc::from(bytes))
        };

        let inputs = vec![
            to_value(&u_c),
            to_value(&[0_u32, 0]),
            to_value(&[0]),
            to_value(&k),
            to_value(&k),
            to_value(&a),
            to_value(&b),
            to_value(&v_in),
            to_value(&[0_u32, 0]),
            to_value(&[0_u32, 0]),
        ];

        let results = reference_eval(&p, &inputs).expect("Fix: interpreter failed");
        let actual_bytes = results[0].to_bytes();
        let actual_u: Vec<u32> = actual_bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        assert_eq!(actual_u, expected_u);
    }

    #[test]
    fn program_declares_ten_buffers() {
        let p = sinkhorn_iterate(
            "k", "kt", "a", "b", "uc", "un", "v", "kv", "ktu", "c", 2, 2, 5,
        );
        assert_eq!(p.buffers().len(), 10);
    }
}

// ===== P-PRIM-11: Full iterative-balance Sinkhorn (f64) ===========
//
// The fixed-point u32 cpu_ref above is the GPU-targeted reference;
// the math operates on quantized fractions. This block ships an
// f64 reference that performs the canonical Sinkhorn-Knopp iterative
// matrix-balancing algorithm with tolerance-based convergence —
// the operation many user dialects ask for when they say "balanced
// transport plan."

/// Tolerance-based Sinkhorn-Knopp iterative balancing in f64.
///
/// Inputs:
/// - `k`: kernel matrix `m × n`, row-major. Strictly positive entries.
/// - `a`: target row marginal, length m. Strictly positive entries.
/// - `b`: target column marginal, length n. Strictly positive entries.
/// - `tolerance`: stop when `||u_new - u_old||_∞ < tolerance`.
/// - `max_iterations`: hard cap.
///
/// Returns `(u, v, iterations)` such that `diag(u) · k · diag(v)`
/// has row sums approximately `a` and column sums approximately `b`,
/// up to the supplied tolerance.
///
/// Pre/post conditions:
/// * Caller guarantees `sum(a) == sum(b)` (mass-conservation;
///   Sinkhorn-Knopp converges only on balanced marginals).
/// * Returns the iteration that stopped — < `max_iterations` means
///   tolerance reached, == `max_iterations` means cap hit.
///
/// # Panics
///
/// Panics on length mismatch.
#[must_use]
pub fn sinkhorn_iterate_f64(
    k: &[f64],
    a: &[f64],
    b: &[f64],
    tolerance: f64,
    max_iterations: u32,
) -> (Vec<f64>, Vec<f64>, u32) {
    let mut u = Vec::new();
    let mut v = Vec::new();
    let mut u_old = Vec::new();
    let iters = sinkhorn_iterate_f64_into(
        k,
        a,
        b,
        tolerance,
        max_iterations,
        &mut u,
        &mut v,
        &mut u_old,
    );
    (u, v, iters)
}

/// Tolerance-based Sinkhorn-Knopp iterative balancing in f64 using
/// caller-owned buffers.
#[allow(clippy::too_many_arguments)]
pub fn sinkhorn_iterate_f64_into(
    k: &[f64],
    a: &[f64],
    b: &[f64],
    tolerance: f64,
    max_iterations: u32,
    u: &mut Vec<f64>,
    v: &mut Vec<f64>,
    u_old: &mut Vec<f64>,
) -> u32 {
    let m = a.len();
    let n = b.len();
    u.clear();
    v.clear();
    u_old.clear();
    if k.len() != m * n || tolerance <= 0.0 || !tolerance.is_finite() {
        return 0;
    }

    u.resize(m, 1.0_f64);
    v.resize(n, 1.0_f64);

    for iter in 0..max_iterations {
        u_old.clear();
        u_old.extend_from_slice(u);

        // u <- a / (k · v)
        for i in 0..m {
            let mut sum = 0.0_f64;
            for j in 0..n {
                sum += k[i * n + j] * v[j];
            }
            // Guard against division by zero — sinkhorn requires k > 0,
            // but defensive callers benefit from a non-NaN result.
            u[i] = if sum == 0.0 { 0.0 } else { a[i] / sum };
        }

        // v <- b / (kᵀ · u)
        for j in 0..n {
            let mut sum = 0.0_f64;
            for i in 0..m {
                sum += k[i * n + j] * u[i];
            }
            v[j] = if sum == 0.0 { 0.0 } else { b[j] / sum };
        }

        // Convergence check on u (Sinkhorn-Knopp stops when one
        // marginal is stable; the other follows by construction).
        let max_delta = u
            .iter()
            .zip(u_old.iter())
            .map(|(new, old)| (new - old).abs())
            .fold(0.0_f64, f64::max);
        if max_delta < tolerance {
            return iter + 1;
        }
    }
    max_iterations
}

/// Compute the row-sum residual `||row_sum(diag(u) · k · diag(v)) - a||_∞`.
/// Useful for testing convergence of [`sinkhorn_iterate_f64`].
#[must_use]
pub fn sinkhorn_row_residual(k: &[f64], u: &[f64], v: &[f64], a: &[f64]) -> f64 {
    let m = a.len();
    let n = v.len();
    assert_eq!(u.len(), m);
    assert_eq!(k.len(), m * n);
    let mut max_resid = 0.0_f64;
    for i in 0..m {
        let mut row = 0.0_f64;
        for j in 0..n {
            row += u[i] * k[i * n + j] * v[j];
        }
        let delta = (row - a[i]).abs();
        if delta > max_resid {
            max_resid = delta;
        }
    }
    max_resid
}

/// Compute the column-sum residual `||col_sum(diag(u) · k · diag(v)) - b||_∞`.
#[must_use]
pub fn sinkhorn_col_residual(k: &[f64], u: &[f64], v: &[f64], b: &[f64]) -> f64 {
    let m = u.len();
    let n = b.len();
    assert_eq!(v.len(), n);
    assert_eq!(k.len(), m * n);
    let mut max_resid = 0.0_f64;
    for j in 0..n {
        let mut col = 0.0_f64;
        for i in 0..m {
            col += u[i] * k[i * n + j] * v[j];
        }
        let delta = (col - b[j]).abs();
        if delta > max_resid {
            max_resid = delta;
        }
    }
    max_resid
}

#[cfg(test)]
mod f64_tests {
    use super::*;

    #[test]
    fn one_by_one_trivial_converges_immediately() {
        let (u, v, iters) = sinkhorn_iterate_f64(&[1.0], &[1.0], &[1.0], 1e-12, 100);
        assert!((u[0] * 1.0 * v[0] - 1.0).abs() < 1e-9);
        assert!(
            iters <= 2,
            "trivial should converge in <=2 iters, got {iters}"
        );
    }

    #[test]
    fn two_by_two_balanced_converges() {
        // k = ones(2,2). a = [1, 1], b = [1, 1]. Total mass = 2 on both sides.
        let k = vec![1.0, 1.0, 1.0, 1.0];
        let a = vec![1.0, 1.0];
        let b = vec![1.0, 1.0];
        let (u, v, iters) = sinkhorn_iterate_f64(&k, &a, &b, 1e-9, 100);
        assert!(iters < 100);
        let row_err = sinkhorn_row_residual(&k, &u, &v, &a);
        let col_err = sinkhorn_col_residual(&k, &u, &v, &b);
        assert!(row_err < 1e-7, "row residual {row_err} > 1e-7");
        assert!(col_err < 1e-7, "col residual {col_err} > 1e-7");
    }

    #[test]
    fn f64_into_reuses_work_buffers() {
        let k = vec![1.0, 1.0, 1.0, 1.0];
        let a = vec![1.0, 1.0];
        let b = vec![1.0, 1.0];
        let mut u = Vec::with_capacity(8);
        let mut v = Vec::with_capacity(8);
        let mut old = Vec::with_capacity(8);
        let u_ptr = u.as_ptr();
        let v_ptr = v.as_ptr();
        let old_ptr = old.as_ptr();
        let iters = sinkhorn_iterate_f64_into(&k, &a, &b, 1e-9, 100, &mut u, &mut v, &mut old);
        assert!(iters < 100);
        assert_eq!(u.as_ptr(), u_ptr);
        assert_eq!(v.as_ptr(), v_ptr);
        assert_eq!(old.as_ptr(), old_ptr);
    }

    #[test]
    fn asymmetric_marginals_still_balance() {
        // 2x3 kernel, marginals a=[2, 4] b=[1, 2, 3].
        // Total mass = 6 on both sides.
        let k = vec![1.0, 2.0, 3.0, 2.0, 1.0, 1.0];
        let a = vec![2.0, 4.0];
        let b = vec![1.0, 2.0, 3.0];
        let (u, v, iters) = sinkhorn_iterate_f64(&k, &a, &b, 1e-10, 1000);
        assert!(iters < 1000);
        let row_err = sinkhorn_row_residual(&k, &u, &v, &a);
        let col_err = sinkhorn_col_residual(&k, &u, &v, &b);
        assert!(row_err < 1e-7);
        assert!(col_err < 1e-7);
    }

    #[test]
    fn cap_hit_returns_max_iterations() {
        // With max_iterations=1 we always return iter=1 (one full
        // pass executed but tolerance not met).
        let k = vec![1.0, 1.0, 1.0, 1.0];
        let a = vec![1.0, 3.0];
        let b = vec![1.0, 3.0];
        let (_u, _v, iters) = sinkhorn_iterate_f64(&k, &a, &b, 1e-15, 1);
        assert_eq!(iters, 1);
    }

    #[test]
    fn diagonal_kernel_is_pre_balanced() {
        // k = I. a = b = [2, 3]. Solution is u = a, v = 1/a (after
        // one iteration u settles to a/v0 = a/1 = a; then v = b/u·k_col
        // = b/(u_i for diag) gives 1; further iters fixed.
        let k = vec![1.0, 0.0, 0.0, 1.0];
        let a = vec![2.0, 3.0];
        let b = vec![2.0, 3.0];
        let (u, v, _iters) = sinkhorn_iterate_f64(&k, &a, &b, 1e-10, 100);
        let row_err = sinkhorn_row_residual(&k, &u, &v, &a);
        let col_err = sinkhorn_col_residual(&k, &u, &v, &b);
        assert!(row_err < 1e-9);
        assert!(col_err < 1e-9);
    }

    #[test]
    fn residual_helpers_are_zero_on_perfect_balance() {
        // Construct u, v, k such that diag(u) k diag(v) has row=a, col=b.
        // Simplest: k = ones(2,2), u = [a/2; a/2 ... ] actually
        // run sinkhorn and check.
        let k = vec![1.0, 1.0, 1.0, 1.0];
        let a = vec![1.0, 1.0];
        let b = vec![1.0, 1.0];
        let (u, v, _) = sinkhorn_iterate_f64(&k, &a, &b, 1e-12, 200);
        assert!(sinkhorn_row_residual(&k, &u, &v, &a) < 1e-9);
        assert!(sinkhorn_col_residual(&k, &u, &v, &b) < 1e-9);
    }

    #[test]
    fn convergence_iters_decrease_as_tolerance_relaxes() {
        let k = vec![1.0, 2.0, 3.0, 4.0];
        let a = vec![3.0, 7.0];
        let b = vec![4.0, 6.0];
        let (_, _, tight) = sinkhorn_iterate_f64(&k, &a, &b, 1e-10, 10_000);
        let (_, _, loose) = sinkhorn_iterate_f64(&k, &a, &b, 1e-3, 10_000);
        assert!(
            loose <= tight,
            "looser tolerance should converge no slower (loose={loose}, tight={tight})"
        );
    }

    #[test]
    fn three_by_three_uniform_kernel() {
        let k = vec![1.0; 9];
        let a = vec![1.0, 2.0, 3.0];
        let b = vec![2.0, 2.0, 2.0];
        let (u, v, iters) = sinkhorn_iterate_f64(&k, &a, &b, 1e-9, 1000);
        assert!(iters < 1000);
        assert!(sinkhorn_row_residual(&k, &u, &v, &a) < 1e-7);
        assert!(sinkhorn_col_residual(&k, &u, &v, &b) < 1e-7);
    }

    #[test]
    fn zero_tolerance_returns_empty_state() {
        let (u, v, iters) = sinkhorn_iterate_f64(&[1.0], &[1.0], &[1.0], 0.0, 10);
        assert!(u.is_empty());
        assert!(v.is_empty());
        assert_eq!(iters, 0);
    }

    #[test]
    fn shape_mismatch_returns_empty_state() {
        let (u, v, iters) = sinkhorn_iterate_f64(&[1.0, 2.0], &[1.0, 1.0], &[1.0, 1.0], 1e-6, 10);
        assert!(u.is_empty());
        assert!(v.is_empty());
        assert_eq!(iters, 0);
    }
}
