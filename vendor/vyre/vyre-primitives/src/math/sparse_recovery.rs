//! Sparse recovery — Iterative Hard Thresholding (IHT) step.
//!
//! Compressed sensing recovers a k-sparse signal from few linear
//! measurements (Donoho 2006, Candès 2008). IHT (Blumensath-Davies
//! 2009) is the simplest GPU-friendly recovery algorithm:
//!
//! ```text
//!   x_{t+1} = H_k(x_t + Aᵀ (y - A x_t))
//! ```
//!
//! where `H_k(z)` keeps the top-k absolute values and zeros the rest.
//!
//! This file ships the **hard-thresholding step** primitive — given
//! the gradient-step output `z = x + Aᵀ(y - Ax)`, find the top-k
//! threshold and zero everything below.
//!
//! The matvec parts (`A x` and `Aᵀ residual`) are
//! [`crate::math::semiring_gemm`] calls in the caller's loop.
//!
//! # Why this primitive is dual-use
//!
//! | Consumer | Use |
//! |---|---|
//! | future `vyre-libs::signal::recovery` | compressed-sensing decoders |
//! | future `vyre-libs::ml::pruning` | structured-sparsity NN pruning |
//! | future `vyre-libs::ml::dictionary` | dictionary learning |
//! | `vyre-foundation::transform` sparse-buffer compaction | when a Region's output is mostly zero, IHT picks the threshold that keeps the top-k non-zeros. The same primitive ships to user signal-recovery dialects. |

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Op id.
pub const OP_ID: &str = "vyre-primitives::math::iht_threshold";

/// Emit the hard-threshold Program.
///
/// Inputs:
/// - `z`: length-`n` u32 buffer (signed values in two's complement —
///   `|z|` is taken at compare time).
/// - `threshold`: single-element u32 buffer; values with absolute
///   value below this are zeroed. Caller computes `threshold` as the
///   k-th largest `|z|` (typically via a sort-then-pick pass).
///
/// Output:
/// - `out`: length-`n` u32 buffer with everything below threshold
///   zeroed.
#[must_use]
pub fn iht_threshold(z: &str, threshold: &str, out: &str, n: u32) -> Program {
    if n == 0 {
        return crate::invalid_output_program(
            OP_ID,
            out,
            DataType::U32,
            format!("Fix: iht_threshold requires n > 0, got {n}."),
        );
    }

    let t = Expr::InvocationId { axis: 0 };
    // We treat z as i32 for the sign-aware threshold compare:
    //   abs_z = (z as i32).abs() as u32
    // The fixed-point convention stores the sign in the high bit and
    // the remaining 31 bits hold the magnitude, so masking yields the
    // threshold magnitude used by this primitive.
    let abs_z = Expr::bitand(Expr::load(z, t.clone()), Expr::u32(0x7FFF_FFFF));
    let thresh_v = Expr::load(threshold, Expr::u32(0));
    let value = Expr::select(
        Expr::ge(abs_z, thresh_v),
        Expr::load(z, t.clone()),
        Expr::u32(0),
    );

    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(n)),
        vec![Node::store(out, t, value)],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(z, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::storage(threshold, 1, BufferAccess::ReadOnly, DataType::U32).with_count(1),
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

/// CPU reference: keep top-k absolute values; zero the rest. Returns
/// the kept values + the threshold (k-th largest `|z|`).
#[must_use]
pub fn iht_top_k_cpu(z: &[f64], k: usize) -> (Vec<f64>, f64) {
    let n = z.len();
    if k >= n {
        return (z.to_vec(), 0.0);
    }
    if k == 0 {
        return (vec![0.0; n], f64::INFINITY);
    }
    // Sort indices by |z| descending; threshold = |z[order[k-1]]|.
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by(|&i, &j| finite_abs_score(z[j]).total_cmp(&finite_abs_score(z[i])));
    let threshold = z[order[k - 1]].abs();
    let mut out = vec![0.0; n];
    for &i in &order[..k] {
        out[i] = z[i];
    }
    (out, threshold)
}

fn finite_abs_score(value: f64) -> f64 {
    let abs = value.abs();
    if abs.is_nan() {
        f64::NEG_INFINITY
    } else {
        abs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-10 * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn cpu_top_2_keeps_largest() {
        let z = vec![0.1, -2.0, 0.5, 3.0, -0.05];
        let (out, thresh) = iht_top_k_cpu(&z, 2);
        // top-2 |z| = 3.0 (idx 3) and 2.0 (idx 1)
        assert!(approx_eq(out[3], 3.0));
        assert!(approx_eq(out[1], -2.0));
        // others zero
        assert!(approx_eq(out[0], 0.0));
        assert!(approx_eq(out[2], 0.0));
        assert!(approx_eq(out[4], 0.0));
        assert!(approx_eq(thresh, 2.0));
    }

    #[test]
    fn cpu_k_equals_n_returns_all() {
        let z = vec![1.0, 2.0, 3.0];
        let (out, _) = iht_top_k_cpu(&z, 3);
        assert_eq!(out, z);
    }

    #[test]
    fn cpu_k_zero_zeros_all() {
        let z = vec![1.0, 2.0, 3.0];
        let (out, thresh) = iht_top_k_cpu(&z, 0);
        for v in out {
            assert!(approx_eq(v, 0.0));
        }
        assert!(thresh.is_infinite());
    }

    #[test]
    fn cpu_preserves_signs() {
        let z = vec![-5.0, 3.0, -7.0];
        let (out, _) = iht_top_k_cpu(&z, 2);
        // top-2 by magnitude: idx 2 (-7) and idx 0 (-5)
        assert!(approx_eq(out[2], -7.0));
        assert!(approx_eq(out[0], -5.0));
        assert!(approx_eq(out[1], 0.0));
    }

    #[test]
    fn ir_program_buffer_layout() {
        let p = iht_threshold("z", "th", "out", 32);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["z", "th", "out"]);
        assert_eq!(p.buffers[0].count(), 32);
        assert_eq!(p.buffers[1].count(), 1);
        assert_eq!(p.buffers[2].count(), 32);
    }

    #[test]
    fn zero_n_traps() {
        let p = iht_threshold("z", "th", "out", 0);
        assert!(p.stats().trap());
    }
}
