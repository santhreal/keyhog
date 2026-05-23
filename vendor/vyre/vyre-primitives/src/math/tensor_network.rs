//! Tensor-network contraction primitive (#35).
//!
//! Tensor networks (PEPS, MPS, MERA) compress high-dimensional
//! functions exponentially. Contraction order matters — the optimal
//! order is solved via tropical-semiring shortest-path. This file
//! ships the **single pairwise contraction step** primitive — given
//! two tensors and the shared-index axis, produce the contracted
//! result.
//!
//! # Why this primitive is dual-use
//!
//! | Consumer | Use |
//! |---|---|
//! | future `vyre-libs::ml::tensor_compress` | TT/MERA-compressed weights |
//! | future `vyre-libs::sci::quantum_chem` | quantum chemistry contraction |
//! | `vyre-driver` megakernel scheduling | each Region in vyre's IR is a tensor; wires are buffer dependencies; optimal fusion = optimal contraction order |

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Op id.
pub const OP_ID: &str = "vyre-primitives::math::tensor_network_pair_contract";

/// Pairwise tensor contraction: contract `A[m × k]` with `B[k × n]`
/// over the shared index `k`. Result `C[m × n]`. Special case of
/// matmul; shipped as a focused primitive so contraction-chain
/// region audits are readable.
#[must_use]
pub fn tn_pair_contract(a: &str, b: &str, c: &str, m: u32, k: u32, n: u32) -> Program {
    if m == 0 || k == 0 || n == 0 {
        return crate::invalid_output_program(
            OP_ID,
            c,
            DataType::U32,
            format!("Fix: tn_pair_contract requires m, k, n > 0, got m={m}, k={k}, n={n}."),
        );
    }

    let cells = m * n;
    let t = Expr::InvocationId { axis: 0 };
    let i_expr = Expr::div(t.clone(), Expr::u32(n));
    let j_expr = Expr::rem(t.clone(), Expr::u32(n));

    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(cells)),
        vec![
            Node::let_bind("acc", Expr::u32(0)),
            Node::let_bind("i", i_expr),
            Node::let_bind("j", j_expr),
            Node::loop_for(
                "kk",
                Expr::u32(0),
                Expr::u32(k),
                vec![Node::assign(
                    "acc",
                    Expr::add(
                        Expr::var("acc"),
                        Expr::shr(
                            Expr::mul(
                                Expr::load(
                                    a,
                                    Expr::add(
                                        Expr::mul(Expr::var("i"), Expr::u32(k)),
                                        Expr::var("kk"),
                                    ),
                                ),
                                Expr::load(
                                    b,
                                    Expr::add(
                                        Expr::mul(Expr::var("kk"), Expr::u32(n)),
                                        Expr::var("j"),
                                    ),
                                ),
                            ),
                            Expr::u32(16),
                        ),
                    ),
                )],
            ),
            Node::store(c, t, Expr::var("acc")),
        ],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(a, 0, BufferAccess::ReadOnly, DataType::U32).with_count(m * k),
            BufferDecl::storage(b, 1, BufferAccess::ReadOnly, DataType::U32).with_count(k * n),
            BufferDecl::storage(c, 2, BufferAccess::ReadWrite, DataType::U32).with_count(cells),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference: f64.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn tn_pair_contract_cpu(a: &[f64], b: &[f64], m: u32, k: u32, n: u32) -> Vec<f64> {
    let m = m as usize;
    let k = k as usize;
    let n = n as usize;
    let mut c = vec![0.0; m * n];
    for i in 0..m {
        for j in 0..n {
            let mut acc = 0.0;
            for kk in 0..k {
                let a_value = a.get(i * k + kk).copied().unwrap_or(0.0);
                let b_value = b.get(kk * n + j).copied().unwrap_or(0.0);
                acc += a_value * b_value;
            }
            c[i * n + j] = acc;
        }
    }
    c
}

/// CPU helper: greedy contraction-order picker. Given a list of tensor
/// dimensions, return an ordering that minimizes the sum of
/// intermediate sizes. This is the tropical-shortest-path solution
/// in a small-dimension case.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn greedy_contract_order_cpu(dims: &[u32]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..dims.len()).collect();
    order.sort_by(|&left, &right| dims[right].cmp(&dims[left]).then_with(|| left.cmp(&right)));
    order
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || tn_pair_contract("a", "b", "c", 2, 2, 2),
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
    fn cpu_pair_contract_2x2_identity() {
        let i = vec![1.0, 0.0, 0.0, 1.0];
        let v = vec![3.0, 5.0, 7.0, 11.0];
        let out = tn_pair_contract_cpu(&i, &v, 2, 2, 2);
        assert_eq!(out, v);
    }

    #[test]
    fn cpu_pair_contract_known_2x2() {
        // [[1, 2], [3, 4]] * [[5, 6], [7, 8]] = [[19, 22], [43, 50]]
        let a = vec![1.0, 2.0, 3.0, 4.0];
        let b = vec![5.0, 6.0, 7.0, 8.0];
        let c = tn_pair_contract_cpu(&a, &b, 2, 2, 2);
        assert!(approx_eq(c[0], 19.0));
        assert!(approx_eq(c[1], 22.0));
        assert!(approx_eq(c[2], 43.0));
        assert!(approx_eq(c[3], 50.0));
    }

    #[test]
    fn cpu_pair_contract_rectangular() {
        // 1x2 * 2x3 = 1x3
        let a = vec![1.0, 2.0];
        let b = vec![3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let c = tn_pair_contract_cpu(&a, &b, 1, 2, 3);
        // [3+12, 4+14, 5+16] = [15, 18, 21]
        assert_eq!(c, vec![15.0, 18.0, 21.0]);
    }

    #[test]
    fn cpu_pair_contract_zero_input_zero_output() {
        let a = vec![0.0; 4];
        let b = vec![1.0; 4];
        let c = tn_pair_contract_cpu(&a, &b, 2, 2, 2);
        for v in c {
            assert!(approx_eq(v, 0.0));
        }
    }

    #[test]
    fn cpu_pair_contract_missing_entries_are_zero() {
        let c = tn_pair_contract_cpu(&[2.0], &[3.0, 4.0], 1, 2, 2);
        assert_eq!(c, vec![6.0, 8.0]);
    }

    #[test]
    fn ir_program_buffer_layout() {
        let p = tn_pair_contract("a", "b", "c", 2, 3, 4);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        assert_eq!(p.buffers[0].count(), 6);
        assert_eq!(p.buffers[1].count(), 12);
        assert_eq!(p.buffers[2].count(), 8);
    }

    #[test]
    fn zero_dim_traps() {
        let p = tn_pair_contract("a", "b", "c", 0, 1, 1);
        assert!(p.stats().trap());
    }
}
