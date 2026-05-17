//! Pass-precondition compilation via #38 knowledge compilation
//! (#38 self-consumer).
//!
//! Closes the recursion thesis for #38 — d-DNNF compilation +
//! evaluation ships to user dialects (neuro-symbolic systems,
//! probabilistic policy engines) AND compiles vyre's optimizer
//! pass-precondition predicates into tractable evaluation circuits.
//!
//! # The self-use
//!
//! Each vyre optimizer pass declares a precondition: a boolean
//! formula over Program features (e.g. "no Region contains atomic
//! ops" AND "all Loop nodes have unit stride"). Today these
//! preconditions are evaluated by hand-rolled match-on-Node
//! traversals — re-implemented per pass with no shared structure.
//!
//! Knowledge compilation reframes the precondition as a
//! propositional formula `φ`. Compile `φ` to d-DNNF (Darwiche 2002):
//! the resulting decision-DNNF circuit can be evaluated in
//! linear time vs the formula's CNF, AND supports model counting
//! and conditioning queries that hand-rolled validators can't.
//!
//! Once preconditions are d-DNNF circuits:
//!
//! - **Conditioning**: "given the current Program features, is
//!   pass X applicable?" reduces to ddnnf_evaluate under the
//!   feature assignment.
//! - **Counterexample search**: "find a feature assignment that
//!   makes the precondition false" is one #SAT query on the d-DNNF.
//! - **Conflict detection**: "passes A and B have contradictory
//!   preconditions" is `φ_A ∧ φ_B` compiled jointly; UNSAT iff they
//!   conflict.
//!
//! # Algorithm
//!
//! ```text
//! 1. each pass declares its precondition as a propositional formula
//!    over Program features
//! 2. host-side compiler: compile the formula to d-DNNF
//!    (one-time per pass, cached)
//! 3. per Program: extract feature assignments, run
//!    ddnnf_evaluate_cpu — returns 1 iff the precondition holds
//! ```
//!
//! This module consumes compiled d-DNNF circuits and evaluates them
//! against Program feature assignments. Circuit construction is owned
//! by the pass framework that supplies the `nodes`, `children`, and
//! topological order buffers.

use vyre_primitives::graph::knowledge_compile::ddnnf_evaluate_cpu;

/// Evaluate a compiled pass-precondition circuit against a Program's
/// feature assignment. Returns 1 iff the precondition holds, 0
/// otherwise. The circuit is the bottom-up-topologically-ordered
/// d-DNNF representation; `var_assignments[i]` is feature i's value
/// (`0` / `1` / `u32::MAX` = unknown).
#[must_use]
pub fn pass_applies(
    nodes: &[(u32, u32, u32)],
    node_var: &[u32],
    children: &[u32],
    var_assignments: &[u32],
    topo_order: &[u32],
) -> u32 {
    use crate::observability::{bump, knowledge_compile_pass_precondition_calls};
    bump(&knowledge_compile_pass_precondition_calls);
    let evals = ddnnf_evaluate_cpu(nodes, node_var, children, var_assignments, topo_order);
    // The root of the topological order is the formula's overall
    // truth value. By d-DNNF construction the root is the LAST node
    // in topo_order.
    if topo_order.is_empty() {
        return 0;
    }
    let Some(root) = topo_order.last().copied() else {
        return 0;
    };
    let root = root as usize;
    evals[root]
}

/// Convenience: does pass X conflict with the current Program?
/// Returns true iff the precondition is unsatisfied at the given
/// feature assignment.
#[must_use]
pub fn pass_conflicts(
    nodes: &[(u32, u32, u32)],
    node_var: &[u32],
    children: &[u32],
    var_assignments: &[u32],
    topo_order: &[u32],
) -> bool {
    pass_applies(nodes, node_var, children, var_assignments, topo_order) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_primitives::graph::knowledge_compile::{AND_NODE, LITERAL_TRUE};

    #[test]
    fn unconditional_pass_always_applies() {
        // Single LITERAL_TRUE node with var 0 unconditionally true.
        let nodes = vec![(LITERAL_TRUE, 0u32, 0u32)];
        let node_var = vec![0u32];
        let children: Vec<u32> = vec![];
        // var 0 = 1 (true).
        let assignments = vec![1u32];
        let topo = vec![0u32];
        assert_eq!(
            pass_applies(&nodes, &node_var, &children, &assignments, &topo),
            1
        );
        assert!(!pass_conflicts(
            &nodes,
            &node_var,
            &children,
            &assignments,
            &topo
        ));
    }

    #[test]
    fn unconditional_pass_blocked_by_false_var() {
        // Same single literal-true node, but var 0 assigned 0 → fails.
        let nodes = vec![(LITERAL_TRUE, 0u32, 0u32)];
        let node_var = vec![0u32];
        let children: Vec<u32> = vec![];
        let assignments = vec![0u32];
        let topo = vec![0u32];
        assert_eq!(
            pass_applies(&nodes, &node_var, &children, &assignments, &topo),
            0
        );
        assert!(pass_conflicts(
            &nodes,
            &node_var,
            &children,
            &assignments,
            &topo
        ));
    }

    #[test]
    fn conjunctive_pass_requires_both() {
        // (LITERAL_TRUE var 0) AND (LITERAL_TRUE var 1) → AND node at index 2.
        let nodes = vec![
            (LITERAL_TRUE, 0u32, 0u32), // node 0: literal var 0
            (LITERAL_TRUE, 0u32, 0u32), // node 1: literal var 1
            (AND_NODE, 0u32, 2u32),     // node 2: AND of children at children[0..2]
        ];
        let node_var = vec![0u32, 1u32, 0u32];
        let children = vec![0u32, 1u32];
        let topo = vec![0u32, 1u32, 2u32];

        // both true.
        let both_true = vec![1u32, 1u32];
        assert_eq!(
            pass_applies(&nodes, &node_var, &children, &both_true, &topo),
            1
        );

        // one false.
        let one_false = vec![1u32, 0u32];
        assert_eq!(
            pass_applies(&nodes, &node_var, &children, &one_false, &topo),
            0
        );
    }

    #[test]
    fn empty_topo_returns_zero() {
        let nodes: Vec<(u32, u32, u32)> = vec![];
        let node_var: Vec<u32> = vec![];
        let children: Vec<u32> = vec![];
        let assignments: Vec<u32> = vec![];
        let topo: Vec<u32> = vec![];
        assert_eq!(
            pass_applies(&nodes, &node_var, &children, &assignments, &topo),
            0
        );
    }
}
