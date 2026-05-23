//! DP-SGD per-sample gradient clip + Gaussian noise primitive (#42).
//!
//! DP-SGD (Abadi 2016) per-sample gradient clipping enforces an L2
//! norm bound `C` on each sample's gradient before averaging across
//! a batch, then adds calibrated Gaussian noise:
//!
//! ```text
//!   g_i_clipped = g_i · min(1, C / ||g_i||_2)
//!   g_batch = (1/B) Σ g_i_clipped + N(0, σ²C²·I)
//! ```
//!
//! Naively this destroys GPU throughput because each sample's clip
//! depends on its individual norm. Recent work (Li-Tramer 2022
//! GhostClip; Subramani 2021) amortizes via power-iteration on the
//! Jacobian-vector product so the per-sample norm is bounded without
//! materialising the full per-sample Jacobian.
//!
//! This file ships the **per-sample clip** primitive: given each
//! sample's gradient slice and its precomputed L2 norm, scale it by
//! `min(1, C / norm)`. Noise injection is a separate primitive
//! (caller composes a Gaussian RNG primitive with elementwise add).
//!
//! # Why this primitive is dual-use
//!
//! | Consumer | Use |
//! |---|---|
//! | future `vyre-libs::privacy::dp_sgd` | calibrated DP-SGD trainers |
//! | future `vyre-libs::ml::robust_optim` | gradient-norm-clipped optimizers |
//! | `vyre-driver` DP telemetry release | bound per-Program telemetry contributions before noise injection |

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Op id.
pub const OP_ID: &str = "vyre-primitives::math::dp_clip_per_sample";

/// Emit the per-sample clip Program. Each lane handles one element of
/// one sample.
///
/// Inputs:
/// - `grads`: row-major `b × d` u32 buffer (b samples × d gradient
///   dimensions). 16.16 fixed-point.
/// - `norms`: length-`b` u32 buffer of L2 norms (16.16). Caller
///   precomputes via `dot_partial` + sqrt.
/// - `clip_norm`: single-element u32 buffer with the bound C.
///
/// Output:
/// - `clipped`: `b × d` u32 buffer with same shape as `grads`.
///
/// Per-cell rule: lane `t = i*d + j` (i = sample, j = dim) loads
/// `s = min(C, norms[i])`, then writes `clipped[t] = grads[t] * s / norms[i]`.
/// When `norms[i] <= C` this leaves the gradient unchanged; otherwise
/// it scales it down to L2 norm exactly C.
#[must_use]
pub fn dp_clip_per_sample(
    grads: &str,
    norms: &str,
    clip_norm: &str,
    clipped: &str,
    b: u32,
    d: u32,
) -> Program {
    if b == 0 {
        return crate::invalid_output_program(
            OP_ID,
            clipped,
            DataType::U32,
            format!("Fix: dp_clip_per_sample requires b > 0, got {b}."),
        );
    }
    if d == 0 {
        return crate::invalid_output_program(
            OP_ID,
            clipped,
            DataType::U32,
            format!("Fix: dp_clip_per_sample requires d > 0, got {d}."),
        );
    }

    let cells = b * d;
    let t = Expr::InvocationId { axis: 0 };
    let i_expr = Expr::div(t.clone(), Expr::u32(d));

    let g = Expr::load(grads, t.clone());
    let n = Expr::load(norms, i_expr);
    let c = Expr::load(clip_norm, Expr::u32(0));

    // safe_norm = max(n, 1) — avoid divide-by-zero.
    let safe_norm = Expr::select(Expr::eq(n.clone(), Expr::u32(0)), Expr::u32(1), n.clone());

    // scale = min(C, n)  → fixed-point
    let scale = Expr::min(c, n);

    // clipped[t] = g * scale / safe_norm
    let value = Expr::div(Expr::mul(g, scale), safe_norm);

    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(cells)),
        vec![Node::store(clipped, t, value)],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(grads, 0, BufferAccess::ReadOnly, DataType::U32).with_count(cells),
            BufferDecl::storage(norms, 1, BufferAccess::ReadOnly, DataType::U32).with_count(b),
            BufferDecl::storage(clip_norm, 2, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage(clipped, 3, BufferAccess::ReadWrite, DataType::U32)
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

/// CPU reference. f64 for clarity.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn dp_clip_per_sample_cpu(
    grads: &[f64],
    norms: &[f64],
    clip_norm: f64,
    b: u32,
    d: u32,
) -> Vec<f64> {
    let b = b as usize;
    let d = d as usize;

    let mut out = vec![0.0; b * d];
    for i in 0..b {
        let n = norms.get(i).copied().unwrap_or(0.0);
        let factor = if n > clip_norm { clip_norm / n } else { 1.0 };
        for j in 0..d {
            let addr = i * d + j;
            out[addr] = grads.get(addr).copied().unwrap_or(0.0) * factor;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-10 * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn cpu_below_threshold_unchanged() {
        // norm 0.5 < clip 1.0 → factor 1, output equals input.
        let g = vec![0.3, 0.4]; // norm = 0.5
        let n = vec![0.5];
        let out = dp_clip_per_sample_cpu(&g, &n, 1.0, 1, 2);
        assert!(approx_eq(out[0], 0.3));
        assert!(approx_eq(out[1], 0.4));
    }

    #[test]
    fn cpu_above_threshold_clipped_to_bound() {
        // norm 5.0, clip 1.0 → factor 0.2.
        let g = vec![3.0, 4.0]; // norm 5.0
        let n = vec![5.0];
        let out = dp_clip_per_sample_cpu(&g, &n, 1.0, 1, 2);
        assert!(approx_eq(out[0], 0.6)); // 3 * 0.2
        assert!(approx_eq(out[1], 0.8)); // 4 * 0.2
                                         // Verify resulting L2 norm = 1.0
        let resulting_norm = (out[0] * out[0] + out[1] * out[1]).sqrt();
        assert!(approx_eq(resulting_norm, 1.0));
    }

    #[test]
    fn cpu_batch_two_samples_clipped_independently() {
        // Sample 0: norm 5.0 (clipped), sample 1: norm 0.5 (passes).
        let g = vec![3.0, 4.0, 0.3, 0.4];
        let n = vec![5.0, 0.5];
        let out = dp_clip_per_sample_cpu(&g, &n, 1.0, 2, 2);
        assert!(approx_eq(out[0], 0.6));
        assert!(approx_eq(out[1], 0.8));
        assert!(approx_eq(out[2], 0.3));
        assert!(approx_eq(out[3], 0.4));
    }

    #[test]
    fn cpu_clip_norm_zero_zeros_all() {
        let g = vec![1.0, 2.0, 3.0];
        let n = vec![3.7416];
        let out = dp_clip_per_sample_cpu(&g, &n, 0.0, 1, 3);
        for v in out {
            assert!(approx_eq(v, 0.0));
        }
    }

    #[test]
    fn cpu_malformed_inputs_fill_missing_lanes_with_zero() {
        let out = dp_clip_per_sample_cpu(&[2.0], &[], 1.0, 2, 2);
        assert_eq!(out.len(), 4);
        assert!(approx_eq(out[0], 2.0));
        assert!(out[1..].iter().all(|&v| approx_eq(v, 0.0)));
    }

    #[test]
    fn ir_program_buffer_layout() {
        let p = dp_clip_per_sample("g", "n", "c", "out", 4, 8);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["g", "n", "c", "out"]);
        assert_eq!(p.buffers[0].count(), 32); // b*d
        assert_eq!(p.buffers[1].count(), 4); // b
        assert_eq!(p.buffers[2].count(), 1);
        assert_eq!(p.buffers[3].count(), 32);
    }

    #[test]
    fn zero_b_traps() {
        let p = dp_clip_per_sample("g", "n", "c", "o", 0, 1);
        assert!(p.stats().trap());
    }

    #[test]
    fn zero_d_traps() {
        let p = dp_clip_per_sample("g", "n", "c", "o", 1, 0);
        assert!(p.stats().trap());
    }
}
