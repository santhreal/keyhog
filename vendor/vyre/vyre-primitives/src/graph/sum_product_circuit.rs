//! Sum-product circuit (probabilistic circuit) evaluator.
//!
//! Sum-product networks (Poon-Domingos 2011, Vergari-Choi 2024) are
//! topologically-ordered weighted DAGs where every marginal is
//! computable in linear time. They sit between graphical models
//! (intractable) and neural networks (no semantics) — tractable
//! probability with calibrated uncertainty.
//!
//! Each node is one of:
//! - **Leaf**: a value `v[i]` (observed evidence, probability 1 if
//!   value matches, 0 otherwise; or a marginal probability).
//! - **Sum**: `out = Σ_c w_c · child_out[c]` over its child set.
//! - **Product**: `out = Π_c child_out[c]` over its child set.
//!
//! Forward evaluation is one bottom-up pass — exactly what
//! [`level_wave_program`](crate::graph::level_wave) was built for. This
//! file ships the per-node evaluator that fits the level-wave
//! workload contract.
//!
//! # Why this primitive is dual-use
//!
//! | Consumer | Use |
//! |---|---|
//! | `vyre-libs::ml::probabilistic` | tractable Bayesian inference |
//! | `vyre-libs::security::risk_score` | calibrated uncertainty on findings |
//! | `vyre-libs::ml::density` | density estimation / anomaly detection |
//! | `vyre-driver/src/cost_model/probabilistic.rs` (#28) | **vyre's dispatch cost model** as probabilistic circuit over Program features → calibrated runtime + uncertainty (paired with #41 conformal intervals) → feed #22 megakernel scheduler as soft constraints |
//!
//! # Encoding
//!
//! Each node carries:
//! - `kind` — 0 = leaf, 1 = sum, 2 = product.
//! - `child_offset`, `child_count` — slice into the child-list buffer.
//! - For sum nodes, an aligned weights slice into the weights buffer.
//!
//! u32 fixed-point 16.16 throughout for outputs and weights.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Op id.
pub const OP_ID: &str = "vyre-primitives::graph::sum_product_evaluate";

/// Node-kind tag: leaf node (carries an evidence/marginal value).
pub const KIND_LEAF: u32 = 0;
/// Node-kind tag: sum node (weighted sum over children, mixture).
pub const KIND_SUM: u32 = 1;
/// Node-kind tag: product node (independence factor over children).
pub const KIND_PRODUCT: u32 = 2;

/// Emit one bottom-up sum-product evaluation step. Caller composes
/// this with [`crate::graph::level_wave::level_wave_program`] to drive
/// the wave from leaves up to the root.
///
/// Buffers:
/// - `kinds`: u32 per node — 0/1/2.
/// - `child_offsets`: u32 per node — start index in `children`.
/// - `child_counts`: u32 per node — number of children.
/// - `children`: u32 list — child node indices (concatenated per node).
/// - `weights`: u32 list — sum-node child weights, indexed parallel
///   to `children` (unused for leaf/product slots).
/// - `leaf_values`: u32 per node — leaf evidence/marginal values
///   (read only when kind == LEAF).
/// - `out`: u32 per node — evaluation output (one per node).
///
/// The dispatch is `n_nodes` lanes; each lane evaluates one node.
/// Children must already be evaluated by the time their parent's lane
/// runs — this primitive does NOT enforce ordering on its own.
/// Callers wrap with `level_wave_program` for the wave harness.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn sum_product_evaluate(
    kinds: &str,
    child_offsets: &str,
    child_counts: &str,
    children: &str,
    weights: &str,
    leaf_values: &str,
    out: &str,
    n_nodes: u32,
    n_edges: u32,
) -> Program {
    if n_nodes == 0 {
        return crate::invalid_output_program(
            OP_ID,
            out,
            DataType::U32,
            format!("Fix: sum_product_evaluate requires n_nodes > 0, got {n_nodes}."),
        );
    }
    if n_edges == 0 {
        return crate::invalid_output_program(
            OP_ID,
            out,
            DataType::U32,
            format!("Fix: sum_product_evaluate requires n_edges > 0, got {n_edges}."),
        );
    }

    let t = Expr::InvocationId { axis: 0 };
    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(n_nodes)),
        vec![
            Node::let_bind("kind", Expr::load(kinds, t.clone())),
            Node::let_bind("co", Expr::load(child_offsets, t.clone())),
            Node::let_bind("cc", Expr::load(child_counts, t.clone())),
            // Leaf: out = leaf_values[t]
            Node::if_then(
                Expr::eq(Expr::var("kind"), Expr::u32(KIND_LEAF)),
                vec![Node::store(
                    out,
                    t.clone(),
                    Expr::load(leaf_values, t.clone()),
                )],
            ),
            // Sum: out = (Σ children[child_idx] * weight) >> 16  (16.16 fixed-point)
            Node::if_then(
                Expr::eq(Expr::var("kind"), Expr::u32(KIND_SUM)),
                vec![
                    Node::let_bind("acc_sum", Expr::u32(0)),
                    Node::loop_for(
                        "k",
                        Expr::u32(0),
                        Expr::var("cc"),
                        vec![
                            Node::let_bind(
                                "child_node",
                                Expr::load(children, Expr::add(Expr::var("co"), Expr::var("k"))),
                            ),
                            Node::let_bind(
                                "w",
                                Expr::load(weights, Expr::add(Expr::var("co"), Expr::var("k"))),
                            ),
                            Node::assign(
                                "acc_sum",
                                Expr::add(
                                    Expr::var("acc_sum"),
                                    Expr::shr(
                                        Expr::mul(
                                            Expr::load(out, Expr::var("child_node")),
                                            Expr::var("w"),
                                        ),
                                        Expr::u32(16),
                                    ),
                                ),
                            ),
                        ],
                    ),
                    Node::store(out, t.clone(), Expr::var("acc_sum")),
                ],
            ),
            // Product: out = (Π children) — fixed-point chain, divide by
            // 2^16 after each multiply to stay in 16.16 range.
            Node::if_then(
                Expr::eq(Expr::var("kind"), Expr::u32(KIND_PRODUCT)),
                vec![
                    Node::let_bind("acc_prod", Expr::u32(1 << 16)), // 1.0 in 16.16
                    Node::loop_for(
                        "kk",
                        Expr::u32(0),
                        Expr::var("cc"),
                        vec![
                            Node::let_bind(
                                "cn",
                                Expr::load(children, Expr::add(Expr::var("co"), Expr::var("kk"))),
                            ),
                            Node::assign(
                                "acc_prod",
                                Expr::shr(
                                    Expr::mul(
                                        Expr::var("acc_prod"),
                                        Expr::load(out, Expr::var("cn")),
                                    ),
                                    Expr::u32(16),
                                ),
                            ),
                        ],
                    ),
                    Node::store(out, t.clone(), Expr::var("acc_prod")),
                ],
            ),
        ],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(kinds, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n_nodes),
            BufferDecl::storage(child_offsets, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n_nodes),
            BufferDecl::storage(child_counts, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n_nodes),
            BufferDecl::storage(children, 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n_edges),
            BufferDecl::storage(weights, 4, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n_edges),
            BufferDecl::storage(leaf_values, 5, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n_nodes),
            BufferDecl::storage(out, 6, BufferAccess::ReadWrite, DataType::U32).with_count(n_nodes),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference: f64 evaluation of a sum-product circuit.
/// `topo_order` is the bottom-up evaluation order (leaves first).
#[must_use]
pub fn sum_product_evaluate_cpu(
    kinds: &[u32],
    child_offsets: &[u32],
    child_counts: &[u32],
    children: &[u32],
    weights: &[f64],
    leaf_values: &[f64],
    topo_order: &[u32],
) -> Vec<f64> {
    let n_nodes = kinds.len();
    let mut out = vec![0.0; n_nodes];
    for &node in topo_order {
        let i = node as usize;
        let kind = kinds[i];
        let co = child_offsets[i] as usize;
        let cc = child_counts[i] as usize;
        match kind {
            x if x == KIND_LEAF => out[i] = leaf_values[i],
            x if x == KIND_SUM => {
                out[i] = (0..cc)
                    .map(|k| {
                        let cn = children[co + k] as usize;
                        weights[co + k] * out[cn]
                    })
                    .sum();
            }
            x if x == KIND_PRODUCT => {
                out[i] = (0..cc).map(|k| out[children[co + k] as usize]).product();
            }
            _ => out[i] = 0.0,
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
    fn cpu_single_leaf() {
        let kinds = vec![KIND_LEAF];
        let off = vec![0];
        let cnt = vec![0];
        let kids: Vec<u32> = vec![];
        let w: Vec<f64> = vec![];
        let leaf = vec![0.7];
        let order = vec![0];
        let out = sum_product_evaluate_cpu(&kinds, &off, &cnt, &kids, &w, &leaf, &order);
        assert!(approx_eq(out[0], 0.7));
    }

    #[test]
    fn cpu_sum_of_two_leaves() {
        // Node 0,1 = leaves with values 0.6, 0.4
        // Node 2 = sum with weights 0.5, 0.5 → 0.3 + 0.2 = 0.5
        let kinds = vec![KIND_LEAF, KIND_LEAF, KIND_SUM];
        let off = vec![0, 0, 0];
        let cnt = vec![0, 0, 2];
        let kids = vec![0, 1];
        let w = vec![0.5, 0.5];
        let leaf = vec![0.6, 0.4, 0.0];
        let order = vec![0, 1, 2];
        let out = sum_product_evaluate_cpu(&kinds, &off, &cnt, &kids, &w, &leaf, &order);
        assert!(approx_eq(out[2], 0.5));
    }

    #[test]
    fn cpu_product_of_two_leaves() {
        let kinds = vec![KIND_LEAF, KIND_LEAF, KIND_PRODUCT];
        let off = vec![0, 0, 0];
        let cnt = vec![0, 0, 2];
        let kids = vec![0, 1];
        let w = vec![0.0, 0.0];
        let leaf = vec![0.6, 0.4, 0.0];
        let order = vec![0, 1, 2];
        let out = sum_product_evaluate_cpu(&kinds, &off, &cnt, &kids, &w, &leaf, &order);
        assert!(approx_eq(out[2], 0.6 * 0.4));
    }

    #[test]
    fn cpu_mixture_distribution() {
        // Build a 2-component mixture:
        //   leaf 0 = 0.8 (component 1 likelihood)
        //   leaf 1 = 0.3 (component 2 likelihood)
        //   sum  2 = 0.4 * 0.8 + 0.6 * 0.3 = 0.32 + 0.18 = 0.5
        let kinds = vec![KIND_LEAF, KIND_LEAF, KIND_SUM];
        let off = vec![0, 0, 0];
        let cnt = vec![0, 0, 2];
        let kids = vec![0, 1];
        let w = vec![0.4, 0.6];
        let leaf = vec![0.8, 0.3, 0.0];
        let order = vec![0, 1, 2];
        let out = sum_product_evaluate_cpu(&kinds, &off, &cnt, &kids, &w, &leaf, &order);
        assert!(approx_eq(out[2], 0.5));
    }

    #[test]
    fn cpu_three_layer_circuit() {
        // 4 leaves → 2 product nodes → 1 sum (mixture of two products)
        // p1 = 0.5 * 0.6 = 0.30
        // p2 = 0.7 * 0.8 = 0.56
        // root = 0.3 * 0.30 + 0.7 * 0.56 = 0.09 + 0.392 = 0.482
        let kinds = vec![
            KIND_LEAF,
            KIND_LEAF,
            KIND_LEAF,
            KIND_LEAF,
            KIND_PRODUCT,
            KIND_PRODUCT,
            KIND_SUM,
        ];
        let off = vec![0, 0, 0, 0, 0, 2, 4];
        let cnt = vec![0, 0, 0, 0, 2, 2, 2];
        let kids = vec![0, 1, 2, 3, 4, 5];
        let w = vec![0.0, 0.0, 0.0, 0.0, 0.3, 0.7];
        let leaf = vec![0.5, 0.6, 0.7, 0.8, 0.0, 0.0, 0.0];
        let order = vec![0, 1, 2, 3, 4, 5, 6];
        let out = sum_product_evaluate_cpu(&kinds, &off, &cnt, &kids, &w, &leaf, &order);
        assert!(approx_eq(out[6], 0.482));
    }

    #[test]
    fn ir_program_buffer_layout() {
        let p = sum_product_evaluate("k", "co", "cc", "ch", "w", "lv", "o", 8, 16);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["k", "co", "cc", "ch", "w", "lv", "o"]);
        // n_nodes-sized
        for i in [0, 1, 2, 5, 6] {
            assert_eq!(p.buffers[i].count(), 8);
        }
        // n_edges-sized
        assert_eq!(p.buffers[3].count(), 16);
        assert_eq!(p.buffers[4].count(), 16);
    }

    #[test]
    fn zero_nodes_traps() {
        let p = sum_product_evaluate("k", "co", "cc", "ch", "w", "lv", "o", 0, 1);
        assert!(p.stats().trap());
    }

    #[test]
    fn zero_edges_traps() {
        let p = sum_product_evaluate("k", "co", "cc", "ch", "w", "lv", "o", 1, 0);
        assert!(p.stats().trap());
    }
}
