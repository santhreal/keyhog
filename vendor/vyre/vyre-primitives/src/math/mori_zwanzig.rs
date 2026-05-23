//! Mori-Zwanzig projection — closed-form coarse-graining of dynamical
//! systems.
//!
//! Mori-Zwanzig (1965) gives an EXACT reduction of a high-dimensional
//! dynamical system to a low-dim "resolved" subsystem plus a memory
//! kernel and orthogonal noise. The Markovian (memory-less)
//! approximation is widely used in scientific ML — Stinis 2020 / Lin
//! 2024 make the M-Z projector learnable.
//!
//! Formal projection:
//!
//! ```text
//!   du/dt = P · F(u) + memory_term + noise
//!   P projects onto the "resolved" subspace (slow modes)
//! ```
//!
//! At primitive level, the M-Z reduction operates on three matrices:
//! `P` (projector, idempotent), `Q = I - P` (orthogonal complement),
//! and the full dynamics operator `L`. The reduced effective operator
//! is `L_eff = P L P + memory(L, P, Q, t)`.
//!
//! This file ships the **Markovian projection step** — given the full
//! dynamics output `F` and the projector matrix `P` (constructed from
//! e.g. randomized SVD over slow-mode trajectories), emit the
//! resolved-subspace forcing `P · F`. Memory-kernel evaluators compose
//! this projection with #43 `ode_step`.
//!
//! # Why this primitive is dual-use
//!
//! | Consumer | Use |
//! |---|---|
//! | future `vyre-libs::sci::climate` | climate / atmospheric coarse-graining |
//! | future `vyre-libs::sci::chemistry` | reaction-diffusion / kinetic Monte Carlo |
//! | future `vyre-libs::ml::scientific` | scientific-ML emulators with memory |
//! | `vyre-foundation::transform` region reduction | group of Regions becomes a macro-node; M-Z gives the optimal effective dynamics for the macro view. |
//!
//! # Composition
//!
//! `mz_project_step(p_matrix, f_vec, out, n)` is one matrix-vector
//! product, isomorphic to a single
//! [`crate::math::semiring_gemm`] call with shape `n × n · n × 1`.
//! Shipped as a focused primitive (rather than indirecting through
//! semiring_gemm) so that region-chain audits show the M-Z projection
//! intent at the call site.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Op id.
pub const OP_ID: &str = "vyre-primitives::math::mori_zwanzig_project_step";

/// Emit `out[i] = Σ_j P[i, j] · f[j]`.
///
/// `P` is row-major `n × n` u32 (16.16). The Markovian-M-Z assumption
/// is that the memory kernel is small — this primitive returns the
/// dominant `P · F` term; callers add a small memory contribution
/// (also a matvec) for the next-order correction.
#[must_use]
pub fn mz_project_step(p_matrix: &str, f_vec: &str, out: &str, n: u32) -> Program {
    if n == 0 {
        return crate::invalid_output_program(
            OP_ID,
            out,
            DataType::U32,
            format!("Fix: mz_project_step requires n > 0, got {n}."),
        );
    }

    let t = Expr::InvocationId { axis: 0 };
    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(n)),
        vec![
            Node::let_bind("acc", Expr::u32(0)),
            Node::let_bind("row_base", Expr::mul(t.clone(), Expr::u32(n))),
            Node::loop_for(
                "j",
                Expr::u32(0),
                Expr::u32(n),
                vec![Node::assign(
                    "acc",
                    Expr::add(
                        Expr::var("acc"),
                        Expr::shr(
                            Expr::mul(
                                Expr::load(
                                    p_matrix,
                                    Expr::add(Expr::var("row_base"), Expr::var("j")),
                                ),
                                Expr::load(f_vec, Expr::var("j")),
                            ),
                            Expr::u32(16),
                        ),
                    ),
                )],
            ),
            Node::store(out, t, Expr::var("acc")),
        ],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(p_matrix, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n * n),
            BufferDecl::storage(f_vec, 1, BufferAccess::ReadOnly, DataType::U32).with_count(n),
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

/// CPU reference, f64.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn mz_project_step_cpu(p_matrix: &[f64], f_vec: &[f64], n: u32) -> Vec<f64> {
    let mut out = Vec::new();
    mz_project_step_cpu_into(p_matrix, f_vec, n, &mut out);
    out
}

/// CPU reference, f64, using caller-owned output storage.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn mz_project_step_cpu_into(p_matrix: &[f64], f_vec: &[f64], n: u32, out: &mut Vec<f64>) {
    let n = n as usize;
    out.clear();
    out.resize(n, 0.0);
    for i in 0..n {
        let mut acc = 0.0;
        for j in 0..n {
            let p = p_matrix.get(i * n + j).copied().unwrap_or(0.0);
            let f = f_vec.get(j).copied().unwrap_or(0.0);
            acc += p * f;
        }
        out[i] = acc;
    }
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || {
            mz_project_step("a", "b", "out", 4)
        },
        None,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-10 * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn cpu_identity_projector_is_passthrough() {
        let i = vec![1.0, 0.0, 0.0, 1.0];
        let f = vec![3.0, 5.0];
        let out = mz_project_step_cpu(&i, &f, 2);
        assert!(approx_eq(out[0], 3.0));
        assert!(approx_eq(out[1], 5.0));
    }

    #[test]
    fn cpu_zero_projector_returns_zero() {
        let p = vec![0.0; 4];
        let f = vec![10.0, 20.0];
        let out = mz_project_step_cpu(&p, &f, 2);
        assert!(approx_eq(out[0], 0.0));
        assert!(approx_eq(out[1], 0.0));
    }

    #[test]
    fn cpu_rank1_projector_collapses_to_dominant_mode() {
        // P = (1/2) [[1, 1], [1, 1]] is the rank-1 projector onto the
        // (1, 1)/sqrt(2) direction (re-normalized to factor 1/2 here).
        // P · [1, 0] = [0.5, 0.5]
        let p = vec![0.5, 0.5, 0.5, 0.5];
        let f = vec![1.0, 0.0];
        let out = mz_project_step_cpu(&p, &f, 2);
        assert!(approx_eq(out[0], 0.5));
        assert!(approx_eq(out[1], 0.5));
    }

    #[test]
    fn cpu_short_inputs_are_zero_padded() {
        let out = mz_project_step_cpu(&[2.0], &[3.0], 2);
        assert_eq!(out, vec![6.0, 0.0]);
    }

    #[test]
    fn cpu_idempotent_projector_squared_equals_self() {
        // For a true projector, P · P · v = P · v.
        let p = vec![1.0, 0.0, 0.0, 0.0]; // diag(1, 0)
        let f = vec![3.0, 5.0];
        let pf = mz_project_step_cpu(&p, &f, 2);
        let ppf = mz_project_step_cpu(&p, &pf, 2);
        assert!(approx_eq(pf[0], ppf[0]));
        assert!(approx_eq(pf[1], ppf[1]));
    }

    #[test]
    fn ir_program_buffer_layout() {
        let p = mz_project_step("P", "f", "out", 8);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["P", "f", "out"]);
        assert_eq!(p.buffers[0].count(), 64);
        assert_eq!(p.buffers[1].count(), 8);
        assert_eq!(p.buffers[2].count(), 8);
    }

    #[test]
    fn zero_n_traps() {
        let p = mz_project_step("P", "f", "out", 0);
        assert!(p.stats().trap());
    }
}
