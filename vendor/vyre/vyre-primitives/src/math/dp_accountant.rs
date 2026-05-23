//! Differential-privacy accountant primitives — Rényi DP composition
//! across Gaussian-mechanism steps with closed-form `(ε, δ)` conversion.
//!
//! # Lego-rule note
//!
//! Most of the DP accountant pipeline composes from primitives that
//! already exist:
//!   - **per-step RDP cost** at order α for a Gaussian mechanism with
//!     noise σ is `α / (2σ²)` — that's this file's primitive,
//!   - **composition over T steps** is `reduce::sum` over the per-step
//!     RDP buffer (no new op needed),
//!   - **convert RDP(α) to (ε, δ)** is `eps = rdp + ln(1/δ) / (α - 1)`,
//!     one `Expr::add` over a host-precomputed scaled log term.
//!
//! Single new primitive shipped: [`crate::math::dp_accountant::gaussian_rdp_step`].
//!
//! # Why this primitive is dual-use
//!
//! | Consumer | Use |
//! |---|---|
//! | future `vyre-libs::privacy::dp_sgd` | per-step accounting in DP-SGD trainers (#42) |
//! | future `vyre-libs::observability::dp_telemetry` | release aggregate dispatch / cache statistics with formal privacy guarantees |
//! | `vyre-driver` DP telemetry release | applies RDP composition before exposing per-Program latency aggregates so the telemetry layer cannot leak individual user code patterns — same Program serves user DP-SGD trainers AND vyre-self telemetry hardening |
//!
//! # Fixed-point convention
//!
//! All buffers are u32 in caller-supplied 16.16 fixed-point.
//! `sigma_squared[i]` must be the scaled value of σ² (NOT σ). The
//! formula assumes that doubling pre-scales α to 2α — i.e. the caller
//! provides `alpha[i]` already scaled, the divide is fixed-point.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::math::gaussian_rdp_step";

/// Emit `out[i] = alpha[i] / (2 * sigma_squared[i])` for `count` lanes.
///
/// This is the Mironov 2017 closed form for the Rényi divergence at
/// order α between `N(0, σ²)` and `N(μ, σ²)` (for any μ ≠ 0): it
/// equals `α μ² / (2 σ²)`. With μ normalized to 1 (the per-coord
/// L2-clipped contribution), the per-step RDP at order α is exactly
/// `α / (2 σ²)`.
#[must_use]
pub fn gaussian_rdp_step(alpha: &str, sigma_squared: &str, out: &str, count: u32) -> Program {
    if count == 0 {
        return crate::invalid_output_program(
            OP_ID,
            out,
            DataType::U32,
            format!("Fix: gaussian_rdp_step requires count > 0, got {count}."),
        );
    }

    let t = Expr::InvocationId { axis: 0 };
    // out = alpha / (2 * sigma_squared)
    let denom = Expr::mul(Expr::u32(2), Expr::load(sigma_squared, t.clone()));
    let value = Expr::div(Expr::load(alpha, t.clone()), denom);

    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(count)),
        vec![Node::store(out, t, value)],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(alpha, 0, BufferAccess::ReadOnly, DataType::U32).with_count(count),
            BufferDecl::storage(sigma_squared, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(count),
            BufferDecl::storage(out, 2, BufferAccess::ReadWrite, DataType::U32).with_count(count),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference (f64 for precision, callers convert to/from their
/// fixed-point convention).
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn gaussian_rdp_step_cpu(alpha: &[f64], sigma_squared: &[f64]) -> Vec<f64> {
    alpha
        .iter()
        .zip(sigma_squared.iter())
        .map(|(&a, &s2)| a / (2.0 * s2))
        .collect()
}

/// Convert RDP(α) to (ε, δ)-DP via Mironov's standard inequality:
/// `ε(δ) = rdp(α) + ln(1/δ) / (α - 1)`. Pure host-side helper because
/// the natural-log is precomputed once per call.
#[must_use]
pub fn rdp_to_dp(rdp: f64, alpha: f64, delta: f64) -> f64 {
    if alpha <= 1.0 || !(delta > 0.0 && delta < 1.0) {
        return f64::INFINITY;
    }
    rdp + (1.0 / delta).ln() / (alpha - 1.0)
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || {
            gaussian_rdp_step("alpha", "sigma_sq", "out", 4)
        },
        None,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f64 = 1e-10;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < EPS * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn cpu_alpha_2_sigma_1() {
        // α=2, σ²=1 → RDP = 2/(2·1) = 1.0
        let r = gaussian_rdp_step_cpu(&[2.0], &[1.0]);
        assert!(approx_eq(r[0], 1.0));
    }

    #[test]
    fn cpu_doubling_alpha_doubles_rdp() {
        let r1 = gaussian_rdp_step_cpu(&[3.0], &[2.0]);
        let r2 = gaussian_rdp_step_cpu(&[6.0], &[2.0]);
        assert!(approx_eq(r2[0], 2.0 * r1[0]));
    }

    #[test]
    fn cpu_doubling_sigma_squared_halves_rdp() {
        let r1 = gaussian_rdp_step_cpu(&[4.0], &[1.0]);
        let r2 = gaussian_rdp_step_cpu(&[4.0], &[2.0]);
        assert!(approx_eq(r2[0], r1[0] / 2.0));
    }

    #[test]
    fn cpu_batch_independent_lanes() {
        let alpha = vec![2.0, 4.0, 8.0];
        let s2 = vec![1.0, 2.0, 4.0];
        let r = gaussian_rdp_step_cpu(&alpha, &s2);
        assert!(approx_eq(r[0], 1.0)); // 2/2
        assert!(approx_eq(r[1], 1.0)); // 4/4
        assert!(approx_eq(r[2], 1.0)); // 8/8
    }

    #[test]
    fn cpu_mismatched_inputs_truncate_to_complete_pairs() {
        let r = gaussian_rdp_step_cpu(&[2.0, 4.0], &[1.0]);
        assert_eq!(r.len(), 1);
        assert!(approx_eq(r[0], 1.0));
    }

    #[test]
    fn rdp_to_dp_monotone_in_rdp() {
        // Larger RDP → larger ε (with α, δ fixed).
        let alpha = 4.0;
        let delta = 1e-5;
        let e1 = rdp_to_dp(0.5, alpha, delta);
        let e2 = rdp_to_dp(1.0, alpha, delta);
        assert!(e2 > e1);
    }

    #[test]
    fn rdp_to_dp_known_value() {
        // α=2, δ=1/e, RDP=0 → ε = ln(e) / (α-1) = 1 / 1 = 1.0
        let eps = rdp_to_dp(0.0, 2.0, std::f64::consts::E.recip());
        assert!(approx_eq(eps, 1.0));
    }

    #[test]
    fn rdp_to_dp_alpha_one_is_conservative_infinity() {
        assert!(rdp_to_dp(0.5, 1.0, 0.5).is_infinite());
    }

    #[test]
    fn rdp_to_dp_delta_zero_is_conservative_infinity() {
        assert!(rdp_to_dp(0.5, 2.0, 0.0).is_infinite());
    }

    #[test]
    fn ir_program_buffer_layout() {
        let p = gaussian_rdp_step("alpha", "s2", "out", 64);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["alpha", "s2", "out"]);
        for buf in p.buffers.iter() {
            assert_eq!(buf.count(), 64);
        }
    }

    #[test]
    fn zero_count_traps() {
        let p = gaussian_rdp_step("a", "s", "o", 0);
        assert!(p.stats().trap());
    }
}
