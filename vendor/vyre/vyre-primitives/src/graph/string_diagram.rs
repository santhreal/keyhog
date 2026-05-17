//! String diagram compilation primitive (#53).
//!
//! String diagrams (Selinger 2010, Coecke-Kissinger ZX) are the visual
//! language of monoidal categories — a generalized tensor network.
//! Recent work (Patterson 2022 DisCoPy) compiles them to numeric
//! tensor contractions.
//!
//! This file ships the **monoidal composition step** primitive —
//! sequential composition `g · f` of two morphisms encoded as small
//! tensors `f: A → B` and `g: B → C`, producing `g · f: A → C`. This
//! is matrix multiplication with categorical intent carried in the
//! stable op id.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Op id.
pub const OP_ID: &str = "vyre-primitives::graph::monoidal_compose";

/// Sequential composition step. Same shape as
/// [`crate::math::tensor_network::tn_pair_contract`]; ships under graph
/// because string diagrams are graphs of morphisms.
#[must_use]
pub fn monoidal_compose(f: &str, g: &str, out: &str, a: u32, b: u32, c: u32) -> Program {
    if a == 0 || b == 0 || c == 0 {
        return crate::invalid_output_program(
            OP_ID,
            out,
            DataType::U32,
            format!("Fix: monoidal_compose requires a, b, c > 0, got a={a}, b={b}, c={c}."),
        );
    }

    let cells = a * c;
    let t = Expr::InvocationId { axis: 0 };
    let i_expr = Expr::div(t.clone(), Expr::u32(c));
    let j_expr = Expr::rem(t.clone(), Expr::u32(c));

    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(cells)),
        vec![
            Node::let_bind("acc", Expr::u32(0)),
            Node::let_bind("i", i_expr),
            Node::let_bind("j", j_expr),
            Node::loop_for(
                "kk",
                Expr::u32(0),
                Expr::u32(b),
                vec![Node::assign(
                    "acc",
                    Expr::add(
                        Expr::var("acc"),
                        Expr::shr(
                            Expr::mul(
                                Expr::load(
                                    f,
                                    Expr::add(
                                        Expr::mul(Expr::var("i"), Expr::u32(b)),
                                        Expr::var("kk"),
                                    ),
                                ),
                                Expr::load(
                                    g,
                                    Expr::add(
                                        Expr::mul(Expr::var("kk"), Expr::u32(c)),
                                        Expr::var("j"),
                                    ),
                                ),
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
            BufferDecl::storage(f, 0, BufferAccess::ReadOnly, DataType::U32).with_count(a * b),
            BufferDecl::storage(g, 1, BufferAccess::ReadOnly, DataType::U32).with_count(b * c),
            BufferDecl::storage(out, 2, BufferAccess::ReadWrite, DataType::U32).with_count(cells),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference.
#[must_use]
pub fn monoidal_compose_cpu(f: &[f64], g: &[f64], a: u32, b: u32, c: u32) -> Vec<f64> {
    let mut out = Vec::new();
    monoidal_compose_cpu_into(f, g, a, b, c, &mut out);
    out
}

/// CPU reference using caller-owned output storage.
pub fn monoidal_compose_cpu_into(f: &[f64], g: &[f64], a: u32, b: u32, c: u32, out: &mut Vec<f64>) {
    let a = a as usize;
    let b = b as usize;
    let c = c as usize;
    out.clear();
    out.resize(a * c, 0.0);
    for i in 0..a {
        for j in 0..c {
            for k in 0..b {
                let f_value = f.get(i * b + k).copied().unwrap_or(0.0);
                let g_value = g.get(k * c + j).copied().unwrap_or(0.0);
                out[i * c + j] += f_value * g_value;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-10 * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn cpu_identity_compose_passthrough() {
        let f = vec![1.0, 2.0, 3.0, 4.0];
        let i = vec![1.0, 0.0, 0.0, 1.0];
        let out = monoidal_compose_cpu(&f, &i, 2, 2, 2);
        assert_eq!(out, f);
    }

    #[test]
    fn cpu_short_inputs_are_zero_padded() {
        let out = monoidal_compose_cpu(&[2.0], &[3.0, 4.0], 1, 2, 2);
        assert_eq!(out, vec![6.0, 8.0]);
    }

    #[test]
    fn cpu_associativity_holds() {
        // (h · g) · f = h · (g · f)
        let f = vec![1.0, 2.0]; // 1x2
        let g = vec![3.0, 4.0]; // 2x1
        let h = vec![5.0]; // 1x1
        let lhs_inner = monoidal_compose_cpu(&f, &g, 1, 2, 1); // 1x1
        let lhs = monoidal_compose_cpu(&lhs_inner, &h, 1, 1, 1); // 1x1
        let rhs_inner = monoidal_compose_cpu(&g, &h, 2, 1, 1); // 2x1
        let rhs = monoidal_compose_cpu(&f, &rhs_inner, 1, 2, 1); // 1x1
        assert!(approx_eq(lhs[0], rhs[0]));
    }

    #[test]
    fn ir_program_buffer_layout() {
        let p = monoidal_compose("f", "g", "h", 2, 3, 4);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        assert_eq!(p.buffers[0].count(), 6);
        assert_eq!(p.buffers[1].count(), 12);
        assert_eq!(p.buffers[2].count(), 8);
    }

    #[test]
    fn zero_a_traps() {
        let p = monoidal_compose("f", "g", "h", 0, 1, 1);
        assert!(p.stats().trap());
    }
}
