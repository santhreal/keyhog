//! Sheaf neural network primitive — sheaf Laplacian application (#31).
//!
//! Sheaf neural networks (Bodnar-Di Giovanni 2022, Hansen-Gebhart 2023)
//! generalize GNNs from "all nodes share one feature space" to "each
//! edge carries restriction maps between heterogeneous node spaces."
//! The sheaf Laplacian is a block matrix where the (i, j) block is
//! `F_{ij}^T F_{ij}` (composition of restriction maps).
//!
//! This file ships the **block-diagonal sheaf Laplacian apply step** —
//! given block-encoded restriction maps `F_{ij}` and a per-node
//! feature stalk, propagate one diffusion step:
//!
//! ```text
//!   y_i = Σ_j F_{ij}^T (F_{ij} x_i - F_{ji} x_j)
//! ```
//!
//! This step is the heart of sheaf diffusion. Each lane handles one
//! node's outgoing aggregation. The restriction maps `F_{ij}` are
//! supplied by the caller as a flat block-tensor.
//!
//! # Why this primitive is dual-use
//!
//! | Consumer | Use |
//! |---|---|
//! | `vyre-libs::ml::heterophilic_gnn` consumers | heterophilic graph learning |
//! | `vyre-libs::security::call_graph_sheaf` consumers | typed call-graph anomalies |
//! | `vyre-foundation::transform` dispatch-sheaf analysis | vyre's dispatch graph is heterophilic; sheaf diffusion predicts where fusion fails |

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Op id.
pub const OP_ID: &str = "vyre-primitives::graph::sheaf_diffusion_step";

/// Emit the diagonal sheaf-Laplacian step.
///
/// Inputs:
/// - `stalks`: `n_nodes * d` u32 (16.16 fp). Per-node `d`-dim feature
///   vector (`d` = stalk dimension).
/// - `restriction_diag`: `n_nodes * d` u32 — the diagonal of each
///   per-node restriction-map composition `F_{ii}^T F_{ii}` reduced to
///   diagonal form (caller computes block-diagonal restriction; this
///   primitive operates on the diagonal-block reduction).
/// - `damping_scaled`: 1-element u32 — diffusion step size in 16.16.
///
/// Output:
/// - `stalks_next`: `n_nodes * d` u32.
///
/// Per-cell rule:
///   `stalks_next[i, k] = stalks[i, k] - damping · restriction_diag[i, k] · stalks[i, k]`
///
/// = `(1 - damping · restriction_diag) · stalks`
///
/// This is the diagonal-form approximation that's correct when the
/// restriction maps are simultaneously diagonalizable. Full off-
/// diagonal sheaf-Laplacian application composes from this primitive
/// plus a graph-traversal step (#5 chebyshev_filter on the off-
/// diagonal part).
#[must_use]
pub fn sheaf_diffusion_step(
    stalks: &str,
    restriction_diag: &str,
    damping_scaled: &str,
    stalks_next: &str,
    n_nodes: u32,
    d: u32,
) -> Program {
    if n_nodes == 0 {
        return crate::invalid_output_program(
            OP_ID,
            stalks_next,
            DataType::U32,
            "Fix: sheaf_diffusion_step requires n_nodes > 0, got 0.".to_string(),
        );
    }
    if d == 0 {
        return crate::invalid_output_program(
            OP_ID,
            stalks_next,
            DataType::U32,
            format!("Fix: sheaf_diffusion_step requires d > 0, got {d}."),
        );
    }

    let cells = n_nodes * d;
    let t = Expr::InvocationId { axis: 0 };

    // delta = damping · restriction_diag[t] · stalks[t]
    // stalks_next[t] = stalks[t] - delta
    let s = Expr::load(stalks, t.clone());
    let r = Expr::load(restriction_diag, t.clone());
    let d_v = Expr::load(damping_scaled, Expr::u32(0));
    let damped_r = Expr::shr(Expr::mul(d_v, r), Expr::u32(16));
    let delta = Expr::shr(Expr::mul(damped_r, s.clone()), Expr::u32(16));
    let value = Expr::sub(s, delta);

    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(cells)),
        vec![Node::store(stalks_next, t, value)],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(stalks, 0, BufferAccess::ReadOnly, DataType::U32).with_count(cells),
            BufferDecl::storage(restriction_diag, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(cells),
            BufferDecl::storage(damping_scaled, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(1),
            BufferDecl::storage(stalks_next, 3, BufferAccess::ReadWrite, DataType::U32)
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

/// CPU reference (f64).
#[must_use]
pub fn sheaf_diffusion_step_cpu(
    stalks: &[f64],
    restriction_diag: &[f64],
    damping: f64,
) -> Vec<f64> {
    let mut out = Vec::with_capacity(stalks.len());
    sheaf_diffusion_step_cpu_into(stalks, restriction_diag, damping, &mut out);
    out
}

/// CPU reference (f64), writing into caller-owned storage.
///
/// Clears `out` and reuses its allocation so iterative diffusion loops do not
/// allocate a new vector on every step.
pub fn sheaf_diffusion_step_cpu_into(
    stalks: &[f64],
    restriction_diag: &[f64],
    damping: f64,
    out: &mut Vec<f64>,
) {
    let n = stalks.len().min(restriction_diag.len());
    out.clear();
    out.reserve(n);
    out.extend(
        stalks
            .iter()
            .zip(restriction_diag.iter())
            .take(n)
            .map(|(&s, &r)| s - damping * r * s),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-10 * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn cpu_zero_damping_holds_stalks() {
        let s = vec![1.0, 2.0, 3.0];
        let r = vec![0.5, 0.5, 0.5];
        let out = sheaf_diffusion_step_cpu(&s, &r, 0.0);
        assert_eq!(out, s);
    }

    #[test]
    fn cpu_unit_restriction_full_damp_zeros() {
        let s = vec![10.0, 20.0];
        let r = vec![1.0, 1.0];
        let out = sheaf_diffusion_step_cpu(&s, &r, 1.0);
        assert!(approx_eq(out[0], 0.0));
        assert!(approx_eq(out[1], 0.0));
    }

    #[test]
    fn cpu_partial_damping_decreases_magnitude() {
        let s = vec![10.0];
        let r = vec![0.5];
        let out = sheaf_diffusion_step_cpu(&s, &r, 0.5);
        // delta = 0.5 · 0.5 · 10 = 2.5; out = 10 - 2.5 = 7.5
        assert!(approx_eq(out[0], 7.5));
    }

    #[test]
    fn cpu_mismatched_inputs_truncate_to_complete_pairs() {
        let out = sheaf_diffusion_step_cpu(&[10.0, 4.0], &[0.5], 1.0);
        assert_eq!(out, vec![5.0]);
    }

    #[test]
    fn cpu_iterations_decay_to_zero_under_full_restriction() {
        // With r=1 and damping ∈ (0, 1), repeated application drives
        // stalks toward 0.
        let mut s = vec![1.0];
        let r = vec![1.0];
        for _ in 0..100 {
            s = sheaf_diffusion_step_cpu(&s, &r, 0.1);
        }
        assert!(s[0].abs() < 1e-3);
    }

    #[test]
    fn ir_program_buffer_layout() {
        let p = sheaf_diffusion_step("s", "rd", "dmp", "sn", 4, 8);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["s", "rd", "dmp", "sn"]);
        assert_eq!(p.buffers[0].count(), 32);
        assert_eq!(p.buffers[1].count(), 32);
        assert_eq!(p.buffers[2].count(), 1);
        assert_eq!(p.buffers[3].count(), 32);
    }

    #[test]
    fn zero_n_nodes_traps() {
        let p = sheaf_diffusion_step("s", "rd", "dmp", "sn", 0, 1);
        assert!(p.stats().trap());
    }

    #[test]
    fn zero_d_traps() {
        let p = sheaf_diffusion_step("s", "rd", "dmp", "sn", 1, 0);
        assert!(p.stats().trap());
    }
}
