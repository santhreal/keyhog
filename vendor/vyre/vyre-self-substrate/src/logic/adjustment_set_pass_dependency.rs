//! Optimizer pass-ordering validity via causal adjustment-set analysis.
//!
//! The pass scheduler models rewrite preconditions as a directed graph:
//! `a[i, j] != 0` means pass `i` can influence pass `j`. A candidate
//! ordering is safe for treatment pass `t` and outcome pass `o` when
//! the ordering does not place an unblocked dependency from `o` back to
//! `t`; such a path would make the proposed order cyclic under the
//! causal intervention "run `t` before `o`".

use crate::dataflow_fixpoint::reachability_closure;

/// Return whether ordering pass `t` before pass `o` is acyclic.
///
/// `adj` is a row-major `n x n` pass-dependency adjacency matrix. The
/// check computes the transitive dependency closure and rejects any
/// ordering where `o` can already reach `t`.
///
/// # Panics
///
/// Panics if `adj.len() != n * n` or either pass index is outside the
/// graph.
#[must_use]
pub fn ordering_is_safe(adj: &[u32], treatment: u32, outcome: u32, n: u32) -> bool {
    use crate::observability::{adjustment_set_pass_dependency_calls, bump};
    bump(&adjustment_set_pass_dependency_calls);
    assert_eq!(
        adj.len(),
        n.saturating_mul(n) as usize,
        "Fix: pass dependency graph must contain n*n cells."
    );
    assert!(treatment < n, "Fix: treatment pass index must be < n.");
    assert!(outcome < n, "Fix: outcome pass index must be < n.");
    if treatment == outcome {
        return true;
    }

    let closure = reachability_closure(adj, n, n);
    closure[(outcome * n + treatment) as usize] == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_reverse_dependency_cycle() {
        let adj = vec![0, 0, 1, 0];
        assert!(!ordering_is_safe(&adj, 0, 1, 2));
    }

    #[test]
    fn accepts_forward_dependency_order() {
        let adj = vec![0, 1, 0, 0];
        assert!(ordering_is_safe(&adj, 0, 1, 2));
    }
}
