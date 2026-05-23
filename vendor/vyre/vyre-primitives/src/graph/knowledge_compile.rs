//! Probabilistic knowledge compilation primitive (#38).
//!
//! Knowledge compilation (Darwiche 2002) compiles a probabilistic
//! logic program into a tractable circuit (d-DNNF, SDD). The
//! compilation step is host-side; the **evaluation** of a compiled
//! circuit is GPU-shaped — exactly what #10 sum_product_circuit
//! does. This file ships a thin wrapper that confirms the compose
//! contract and adds a host-side d-DNNF satisfiability oracle helper.
//!
//! # Why this primitive is dual-use
//!
//! | Consumer | Use |
//! |---|---|
//! | `vyre-libs::ml::probabilistic_logic` | neuro-symbolic systems |
//! | `vyre-libs::security::policy_engine` | rule-conflict resolution as probabilistic logic |

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// d-DNNF "literal kind" tag.
pub const LITERAL_TRUE: u32 = 1;
/// d-DNNF "literal kind" tag for false.
pub const LITERAL_FALSE: u32 = 2;
/// AND node tag.
pub const AND_NODE: u32 = 3;
/// OR node tag.
pub const OR_NODE: u32 = 4;

/// Op id for the GPU-shaped d-DNNF evaluator.
pub const OP_ID: &str = "vyre-primitives::graph::ddnnf_evaluate";

/// Emit one bottom-up d-DNNF evaluation step. The dispatch is
/// `n_nodes` lanes; each lane evaluates one node from already-evaluated
/// children. Callers compose this with `level_wave_program` or another
/// topological wave scheduler when parent nodes must wait for child
/// outputs.
///
/// Buffers:
/// - `node_kinds`: u32 per node, using [`LITERAL_TRUE`],
///   [`LITERAL_FALSE`], [`AND_NODE`], [`OR_NODE`].
/// - `node_var`: u32 per node, meaningful for literal nodes.
/// - `child_offsets`: u32 per node into `children`.
/// - `child_counts`: u32 per node.
/// - `children`: concatenated child node indices.
/// - `var_assignments`: u32 per variable, 0/1/`u32::MAX` unknown.
/// - `out`: u32 per node.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn ddnnf_evaluate(
    node_kinds: &str,
    node_var: &str,
    child_offsets: &str,
    child_counts: &str,
    children: &str,
    var_assignments: &str,
    out: &str,
    n_nodes: u32,
    n_children: u32,
    n_vars: u32,
) -> Program {
    match try_ddnnf_evaluate(
        node_kinds,
        node_var,
        child_offsets,
        child_counts,
        children,
        var_assignments,
        out,
        n_nodes,
        n_children,
        n_vars,
    ) {
        Ok(program) => program,
        Err(error) => {
            eprintln!("{error}");
            crate::invalid_output_program(OP_ID, out, DataType::U32, error)
        }
    }
}

/// Emit one bottom-up d-DNNF evaluation step with checked domain shape.
#[allow(clippy::too_many_arguments)]
pub fn try_ddnnf_evaluate(
    node_kinds: &str,
    node_var: &str,
    child_offsets: &str,
    child_counts: &str,
    children: &str,
    var_assignments: &str,
    out: &str,
    n_nodes: u32,
    n_children: u32,
    n_vars: u32,
) -> Result<Program, String> {
    if n_nodes == 0 {
        return Err(format!(
            "Fix: ddnnf_evaluate requires n_nodes > 0, got {n_nodes}."
        ));
    }
    if n_vars == 0 {
        return Err(format!(
            "Fix: ddnnf_evaluate requires n_vars > 0, got {n_vars}."
        ));
    }

    let lane = Expr::InvocationId { axis: 0 };
    let child_index = Expr::add(Expr::var("child_base"), Expr::var("k"));
    let body = vec![Node::if_then(
        Expr::lt(lane.clone(), Expr::u32(n_nodes)),
        vec![
            Node::let_bind("kind", Expr::load(node_kinds, lane.clone())),
            Node::let_bind("var_id", Expr::load(node_var, lane.clone())),
            Node::let_bind("child_base", Expr::load(child_offsets, lane.clone())),
            Node::let_bind("child_count", Expr::load(child_counts, lane.clone())),
            Node::if_then(
                Expr::eq(Expr::var("kind"), Expr::u32(LITERAL_TRUE)),
                vec![
                    Node::let_bind(
                        "assigned_true",
                        Expr::load(var_assignments, Expr::var("var_id")),
                    ),
                    Node::store(
                        out,
                        lane.clone(),
                        Expr::select(
                            Expr::or(
                                Expr::eq(Expr::var("assigned_true"), Expr::u32(1)),
                                Expr::eq(Expr::var("assigned_true"), Expr::u32(u32::MAX)),
                            ),
                            Expr::u32(1),
                            Expr::u32(0),
                        ),
                    ),
                ],
            ),
            Node::if_then(
                Expr::eq(Expr::var("kind"), Expr::u32(LITERAL_FALSE)),
                vec![
                    Node::let_bind(
                        "assigned_false",
                        Expr::load(var_assignments, Expr::var("var_id")),
                    ),
                    Node::store(
                        out,
                        lane.clone(),
                        Expr::select(
                            Expr::or(
                                Expr::eq(Expr::var("assigned_false"), Expr::u32(0)),
                                Expr::eq(Expr::var("assigned_false"), Expr::u32(u32::MAX)),
                            ),
                            Expr::u32(1),
                            Expr::u32(0),
                        ),
                    ),
                ],
            ),
            Node::if_then(
                Expr::eq(Expr::var("kind"), Expr::u32(AND_NODE)),
                vec![
                    Node::let_bind("acc_and", Expr::u32(1)),
                    Node::loop_for(
                        "k",
                        Expr::u32(0),
                        Expr::var("child_count"),
                        vec![
                            Node::let_bind("child_node", Expr::load(children, child_index.clone())),
                            Node::assign(
                                "acc_and",
                                Expr::mul(
                                    Expr::var("acc_and"),
                                    Expr::load(out, Expr::var("child_node")),
                                ),
                            ),
                        ],
                    ),
                    Node::store(out, lane.clone(), Expr::var("acc_and")),
                ],
            ),
            Node::if_then(
                Expr::eq(Expr::var("kind"), Expr::u32(OR_NODE)),
                vec![
                    Node::let_bind("acc_or", Expr::u32(0)),
                    Node::loop_for(
                        "kk",
                        Expr::u32(0),
                        Expr::var("child_count"),
                        vec![
                            Node::let_bind(
                                "or_child_node",
                                Expr::load(
                                    children,
                                    Expr::add(Expr::var("child_base"), Expr::var("kk")),
                                ),
                            ),
                            Node::assign(
                                "acc_or",
                                Expr::add(
                                    Expr::var("acc_or"),
                                    Expr::load(out, Expr::var("or_child_node")),
                                ),
                            ),
                        ],
                    ),
                    Node::store(out, lane.clone(), Expr::var("acc_or")),
                ],
            ),
            Node::if_then(
                Expr::and(
                    Expr::and(
                        Expr::ne(Expr::var("kind"), Expr::u32(LITERAL_TRUE)),
                        Expr::ne(Expr::var("kind"), Expr::u32(LITERAL_FALSE)),
                    ),
                    Expr::and(
                        Expr::ne(Expr::var("kind"), Expr::u32(AND_NODE)),
                        Expr::ne(Expr::var("kind"), Expr::u32(OR_NODE)),
                    ),
                ),
                vec![Node::store(out, lane.clone(), Expr::u32(0))],
            ),
        ],
    )];

    Ok(Program::wrapped(
        vec![
            BufferDecl::storage(node_kinds, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n_nodes),
            BufferDecl::storage(node_var, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n_nodes),
            BufferDecl::storage(child_offsets, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n_nodes),
            BufferDecl::storage(child_counts, 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n_nodes),
            BufferDecl::storage(children, 4, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n_children.max(1)),
            BufferDecl::storage(var_assignments, 5, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n_vars),
            BufferDecl::storage(out, 6, BufferAccess::ReadWrite, DataType::U32).with_count(n_nodes),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    ))
}

/// CPU helper: evaluate a d-DNNF compiled circuit under a partial
/// variable assignment. Returns the model count weighted by node
/// types (the canonical KC inference query).
///
/// `var_assignments[var_id] = 0/1/u32::MAX` (unknown).
/// `nodes[i] = (kind, child_offset, child_count)` row-major.
/// `node_var[i]` = variable id (only meaningful for literal nodes).
/// `topo_order` is the bottom-up evaluation order.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn ddnnf_evaluate_cpu(
    nodes: &[(u32, u32, u32)],
    node_var: &[u32],
    children: &[u32],
    var_assignments: &[u32],
    topo_order: &[u32],
) -> Vec<u32> {
    match try_ddnnf_evaluate_cpu(nodes, node_var, children, var_assignments, topo_order) {
        Ok(out) => out,
        Err(error) => {
            eprintln!("{error}");
            Vec::new()
        }
    }
}

/// CPU helper with checked compiled-circuit indexing and arithmetic.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn try_ddnnf_evaluate_cpu(
    nodes: &[(u32, u32, u32)],
    node_var: &[u32],
    children: &[u32],
    var_assignments: &[u32],
    topo_order: &[u32],
) -> Result<Vec<u32>, String> {
    let n_nodes = nodes.len();
    let mut out = vec![0u32; n_nodes];
    for &node in topo_order {
        let i = node as usize;
        let Some(&(kind, co, cc)) = nodes.get(i) else {
            return Err(format!(
                "ddnnf_evaluate CPU oracle topo node {node} is outside node_count={n_nodes}. Fix: rebuild the compiled-circuit topological order."
            ));
        };
        match kind {
            LITERAL_TRUE => {
                let Some(&var_id) = node_var.get(i) else {
                    return Err(format!(
                        "ddnnf_evaluate CPU oracle missing node_var for literal node {i}. Fix: pass one variable slot per compiled node."
                    ));
                };
                let v = var_id as usize;
                let Some(&assigned) = var_assignments.get(v) else {
                    return Err(format!(
                        "ddnnf_evaluate CPU oracle literal node {i} references var {v} outside assignment_count={}. Fix: pass a complete assignment vector.",
                        var_assignments.len()
                    ));
                };
                out[i] = if assigned == 1 || assigned == u32::MAX {
                    1
                } else {
                    0
                };
            }
            LITERAL_FALSE => {
                let Some(&var_id) = node_var.get(i) else {
                    return Err(format!(
                        "ddnnf_evaluate CPU oracle missing node_var for literal node {i}. Fix: pass one variable slot per compiled node."
                    ));
                };
                let v = var_id as usize;
                let Some(&assigned) = var_assignments.get(v) else {
                    return Err(format!(
                        "ddnnf_evaluate CPU oracle literal node {i} references var {v} outside assignment_count={}. Fix: pass a complete assignment vector.",
                        var_assignments.len()
                    ));
                };
                out[i] = if assigned == 0 || assigned == u32::MAX {
                    1
                } else {
                    0
                };
            }
            AND_NODE => {
                let mut acc = 1u32;
                for k in 0..cc as usize {
                    let child_index = (co as usize).checked_add(k).ok_or_else(|| {
                        format!(
                            "ddnnf_evaluate CPU oracle child offset overflow at node {i}. Fix: rebuild child_offsets before parity comparison."
                        )
                    })?;
                    let Some(&child_node) = children.get(child_index) else {
                        return Err(format!(
                            "ddnnf_evaluate CPU oracle node {i} child index {child_index} exceeds child_count={}. Fix: pass a complete child list.",
                            children.len()
                        ));
                    };
                    let cn = child_node as usize;
                    let Some(&child_value) = out.get(cn) else {
                        return Err(format!(
                            "ddnnf_evaluate CPU oracle node {i} references child node {cn} outside node_count={n_nodes}. Fix: rebuild compiled child ids."
                        ));
                    };
                    acc = acc.checked_mul(child_value).ok_or_else(|| {
                        format!(
                            "ddnnf_evaluate CPU oracle AND node {i} model count overflowed u32. Fix: shard or widen model-count accumulation."
                        )
                    })?;
                }
                out[i] = acc;
            }
            OR_NODE => {
                let mut acc = 0u32;
                for k in 0..cc as usize {
                    let child_index = (co as usize).checked_add(k).ok_or_else(|| {
                        format!(
                            "ddnnf_evaluate CPU oracle child offset overflow at node {i}. Fix: rebuild child_offsets before parity comparison."
                        )
                    })?;
                    let Some(&child_node) = children.get(child_index) else {
                        return Err(format!(
                            "ddnnf_evaluate CPU oracle node {i} child index {child_index} exceeds child_count={}. Fix: pass a complete child list.",
                            children.len()
                        ));
                    };
                    let cn = child_node as usize;
                    let Some(&child_value) = out.get(cn) else {
                        return Err(format!(
                            "ddnnf_evaluate CPU oracle node {i} references child node {cn} outside node_count={n_nodes}. Fix: rebuild compiled child ids."
                        ));
                    };
                    acc = acc.checked_add(child_value).ok_or_else(|| {
                        format!(
                            "ddnnf_evaluate CPU oracle OR node {i} model count overflowed u32. Fix: shard or widen model-count accumulation."
                        )
                    })?;
                }
                out[i] = acc;
            }
            _ => {
                out[i] = 0;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_single_true_literal_with_assigned_var() {
        // 1 node, kind=LITERAL_TRUE, var 0 assigned to 1 → out = 1.
        let nodes = vec![(LITERAL_TRUE, 0, 0)];
        let node_var = vec![0];
        let children = vec![];
        let assigns = vec![1];
        let order = vec![0];
        let out = ddnnf_evaluate_cpu(&nodes, &node_var, &children, &assigns, &order);
        assert_eq!(out[0], 1);
    }

    #[test]
    fn cpu_single_true_literal_with_unset_var() {
        // var 0 unknown → output 1 (counts both true assignments).
        let nodes = vec![(LITERAL_TRUE, 0, 0)];
        let node_var = vec![0];
        let children = vec![];
        let assigns = vec![u32::MAX];
        let order = vec![0];
        let out = ddnnf_evaluate_cpu(&nodes, &node_var, &children, &assigns, &order);
        assert_eq!(out[0], 1);
    }

    #[test]
    fn cpu_and_of_two_literals() {
        // (x_0=true) AND (x_1=true), both unknown → mc = 1
        let nodes = vec![(LITERAL_TRUE, 0, 0), (LITERAL_TRUE, 0, 0), (AND_NODE, 0, 2)];
        let node_var = vec![0, 1, 0];
        let children = vec![0, 1];
        let assigns = vec![u32::MAX; 2];
        let order = vec![0, 1, 2];
        let out = ddnnf_evaluate_cpu(&nodes, &node_var, &children, &assigns, &order);
        assert_eq!(out[2], 1);
    }

    #[test]
    fn cpu_or_of_two_literals_counts_both() {
        // (x_0=true) OR (x_1=true), both unknown → mc = 2
        let nodes = vec![(LITERAL_TRUE, 0, 0), (LITERAL_TRUE, 0, 0), (OR_NODE, 0, 2)];
        let node_var = vec![0, 1, 0];
        let children = vec![0, 1];
        let assigns = vec![u32::MAX; 2];
        let order = vec![0, 1, 2];
        let out = ddnnf_evaluate_cpu(&nodes, &node_var, &children, &assigns, &order);
        assert_eq!(out[2], 2);
    }

    #[test]
    fn cpu_partial_assignment_constrains_count() {
        // With var 0 fixed to true, the OR (x_0 OR x_1) becomes
        // mc = 1 (x_0 satisfied) for any x_1.
        let nodes = vec![(LITERAL_TRUE, 0, 0), (LITERAL_TRUE, 0, 0), (OR_NODE, 0, 2)];
        let node_var = vec![0, 1, 0];
        let children = vec![0, 1];
        let assigns = vec![1, 0]; // x_0 = true, x_1 = false
        let order = vec![0, 1, 2];
        let out = ddnnf_evaluate_cpu(&nodes, &node_var, &children, &assigns, &order);
        // out[0] = 1 (x_0 = true literal evaluates to 1)
        // out[1] = 0 (x_1 = true literal but x_1 is assigned false)
        // out[2] = 1 + 0 = 1
        assert_eq!(out[2], 1);
    }

    #[test]
    fn checked_cpu_oracle_rejects_missing_assignment() {
        let nodes = vec![(LITERAL_TRUE, 0, 0)];
        let node_var = vec![7];
        let children = vec![];
        let assigns = vec![u32::MAX];
        let order = vec![0];
        let error = try_ddnnf_evaluate_cpu(&nodes, &node_var, &children, &assigns, &order)
            .expect_err("checked d-DNNF oracle must reject missing variable assignments");

        assert!(
            error.contains("outside assignment_count"),
            "error should describe the missing assignment: {error}"
        );
    }

    #[test]
    fn checked_cpu_oracle_rejects_missing_child() {
        let nodes = vec![(LITERAL_TRUE, 0, 0), (AND_NODE, 0, 1)];
        let node_var = vec![0, 0];
        let children = vec![];
        let assigns = vec![u32::MAX];
        let order = vec![0, 1];
        let error = try_ddnnf_evaluate_cpu(&nodes, &node_var, &children, &assigns, &order)
            .expect_err("checked d-DNNF oracle must reject missing child list entries");

        assert!(
            error.contains("exceeds child_count"),
            "error should describe the missing child entry: {error}"
        );
    }

    #[test]
    fn gpu_program_builder_exposes_ddnnf_buffers() {
        let program = ddnnf_evaluate(
            "kinds",
            "node_var",
            "child_offsets",
            "child_counts",
            "children",
            "assignments",
            "out",
            3,
            2,
            2,
        );
        assert_eq!(program.buffers().len(), 7);
        assert_eq!(program.workgroup_size(), [256, 1, 1]);
        assert!(
            program
                .entry()
                .iter()
                .any(|node| matches!(node, vyre_foundation::ir::Node::Region { generator, .. } if generator.as_str() == OP_ID))
        );
    }

    #[test]
    fn gpu_program_builder_rejects_empty_node_count_with_trap_program() {
        let program = ddnnf_evaluate(
            "kinds",
            "node_var",
            "child_offsets",
            "child_counts",
            "children",
            "assignments",
            "out",
            0,
            0,
            1,
        );
        assert_eq!(program.buffers().len(), 1);
        assert!(
            program
                .entry()
                .iter()
                .any(|node| matches!(node, vyre_foundation::ir::Node::Region { body, .. } if body.iter().any(|inner| matches!(inner, vyre_foundation::ir::Node::Trap { .. }))))
        );
    }

    #[test]
    fn checked_gpu_builder_rejects_empty_var_domain() {
        let error = try_ddnnf_evaluate(
            "kinds",
            "node_var",
            "child_offsets",
            "child_counts",
            "children",
            "assignments",
            "out",
            1,
            0,
            0,
        )
        .expect_err("checked d-DNNF builder must reject empty variable domains");

        assert!(
            error.contains("requires n_vars > 0"),
            "error should describe the invalid variable domain: {error}"
        );
    }

    #[test]
    fn gpu_builder_source_has_checked_api_without_panics() {
        let source = include_str!("knowledge_compile.rs");
        let builder_source = source
            .split("pub fn ddnnf_evaluate(")
            .nth(1)
            .expect("d-DNNF GPU builder source must be present")
            .split("/// CPU helper:")
            .next()
            .expect("d-DNNF GPU builder source must precede CPU oracle");

        assert!(
            builder_source.contains("pub fn try_ddnnf_evaluate(")
                && !builder_source.contains(concat!("panic", "!("))
                && !builder_source.contains(".unwrap_or_else("),
            "Fix: ddnnf_evaluate must expose a checked release API and avoid production panics."
        );
    }
}
