//! Backend-neutral pipeline-cache invalidation helpers.
//!
//! Backends provide their cache keys and lineage cells; this module owns
//! the shared causal-impact/provenance walk so the backend crates do not
//! depend on self-substrate implementation modules directly.

#[cfg(feature = "self-substrate-adapters")]
use vyre_self_substrate::do_calculus_change_impact::{
    predict_impact_with_scratch, DoCalculusImpactScratch,
};
#[cfg(feature = "self-substrate-adapters")]
use vyre_self_substrate::scallop_provenance::{
    cpu_provenance_closure_with_scratch, ScallopProvenanceScratch,
};

/// Reusable scratch for shared pipeline-cache invalidation.
#[derive(Debug, Default)]
pub struct CacheInvalidationScratch {
    #[cfg(feature = "self-substrate-adapters")]
    impact: DoCalculusImpactScratch,
    #[cfg(feature = "self-substrate-adapters")]
    provenance: ScallopProvenanceScratch,
}

/// Compute a 0/1 impact mask for cache entries.
///
/// When `self-substrate-adapters` is disabled, this uses the built-in CPU
/// fallback below: transitive impact over `rule_adj` plus transitive provenance
/// over `state | join_rules`. Backend crates can enable the shared driver
/// feature for the self-substrate implementation, but the default path remains
/// conservative and functional.
pub fn impacted_entries_into(
    intervention_mask: &[u32],
    rule_adj: &[u32],
    state: &[u32],
    join_rules: &[u32],
    n: u32,
    max_iterations: u32,
    lineage_cells: &[u32],
    out: &mut Vec<u32>,
    _scratch: &mut CacheInvalidationScratch,
) {
    out.clear();
    out.resize(lineage_cells.len(), 0);

    #[cfg(not(feature = "self-substrate-adapters"))]
    {
        cpu_impacted_entries_fallback(
            intervention_mask,
            rule_adj,
            state,
            join_rules,
            n,
            max_iterations,
            lineage_cells,
            out,
        );
    }

    #[cfg(feature = "self-substrate-adapters")]
    {
        let n_us = n as usize;
        if n_us == 0
            || intervention_mask.len() < n_us
            || rule_adj.len() < n_us.saturating_mul(n_us)
            || state.len() < n_us.saturating_mul(n_us)
            || join_rules.len() < n_us.saturating_mul(n_us)
        {
            return;
        }

        predict_impact_with_scratch(rule_adj, intervention_mask, n, &mut _scratch.impact);
        let iterations = cpu_provenance_closure_with_scratch(
            state,
            join_rules,
            n,
            max_iterations,
            &mut _scratch.provenance,
        );
        if max_iterations != 0 && iterations > max_iterations {
            return;
        }

        let impacted_rules = _scratch.impact.impact_mask();
        let closure = _scratch.provenance.closure();
        let Some(matrix_len) = n_us.checked_mul(n_us) else {
            return;
        };
        if impacted_rules.len() < n_us || closure.len() < matrix_len {
            return;
        }

        for (entry_idx, &cell) in lineage_cells.iter().enumerate() {
            let cell = cell as usize;
            if cell >= n_us {
                continue;
            }
            let row_start = cell * n_us;
            let row = &closure[row_start..row_start + n_us];
            if row
                .iter()
                .zip(impacted_rules.iter())
                .any(|(&bitset, &impacted)| bitset != 0 && impacted != 0)
            {
                out[entry_idx] = 1;
            }
        }
    }
}

#[cfg(not(feature = "self-substrate-adapters"))]
fn cpu_impacted_entries_fallback(
    intervention_mask: &[u32],
    rule_adj: &[u32],
    state: &[u32],
    join_rules: &[u32],
    n: u32,
    max_iterations: u32,
    lineage_cells: &[u32],
    out: &mut [u32],
) {
    let n_us = n as usize;
    let Some(matrix_len) = n_us.checked_mul(n_us) else {
        return;
    };
    if n_us == 0
        || intervention_mask.len() < n_us
        || rule_adj.len() < matrix_len
        || state.len() < matrix_len
        || join_rules.len() < matrix_len
    {
        return;
    }

    let mut impacted = vec![0u32; n_us];
    for idx in 0..n_us {
        impacted[idx] = u32::from(intervention_mask[idx] != 0);
    }
    transitive_reachability_from_adjacency(rule_adj, n_us, max_iterations, &mut impacted);

    let mut provenance = vec![0u32; matrix_len];
    for idx in 0..matrix_len {
        provenance[idx] = u32::from(state[idx] != 0 || join_rules[idx] != 0);
    }
    transitive_closure_bool_matrix(&mut provenance, n_us, max_iterations);

    for (entry_idx, &cell) in lineage_cells.iter().enumerate() {
        let cell = cell as usize;
        if cell >= n_us {
            continue;
        }
        let row = &provenance[cell * n_us..cell * n_us + n_us];
        if row
            .iter()
            .zip(impacted.iter())
            .any(|(&reaches, &is_impacted)| reaches != 0 && is_impacted != 0)
            || impacted[cell] != 0
        {
            out[entry_idx] = 1;
        }
    }
}

#[cfg(not(feature = "self-substrate-adapters"))]
fn transitive_reachability_from_adjacency(
    adjacency: &[u32],
    n: usize,
    max_iterations: u32,
    reached: &mut [u32],
) {
    let limit = iteration_limit(n, max_iterations);
    for _ in 0..limit {
        let mut changed = false;
        let prev = reached.to_vec();
        for src in 0..n {
            if prev[src] == 0 {
                continue;
            }
            let row = &adjacency[src * n..src * n + n];
            for dst in 0..n {
                if row[dst] != 0 && reached[dst] == 0 {
                    reached[dst] = 1;
                    changed = true;
                }
            }
        }
        if !changed {
            return;
        }
    }
}

#[cfg(not(feature = "self-substrate-adapters"))]
fn transitive_closure_bool_matrix(matrix: &mut [u32], n: usize, max_iterations: u32) {
    let limit = iteration_limit(n, max_iterations);
    for _ in 0..limit {
        let previous = matrix.to_vec();
        let mut changed = false;
        for src in 0..n {
            for mid in 0..n {
                if previous[src * n + mid] == 0 {
                    continue;
                }
                for dst in 0..n {
                    if previous[mid * n + dst] != 0 && matrix[src * n + dst] == 0 {
                        matrix[src * n + dst] = 1;
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            return;
        }
    }
}

#[cfg(not(feature = "self-substrate-adapters"))]
fn iteration_limit(n: usize, max_iterations: u32) -> usize {
    if max_iterations == 0 {
        n
    } else {
        (max_iterations as usize).min(n)
    }
}

/// Compute a 0/1 impact mask using temporary scratch.
#[must_use]
pub fn impacted_entries(
    intervention_mask: &[u32],
    rule_adj: &[u32],
    state: &[u32],
    join_rules: &[u32],
    n: u32,
    max_iterations: u32,
    lineage_cells: &[u32],
) -> Vec<u32> {
    let mut out = Vec::with_capacity(lineage_cells.len());
    let mut scratch = CacheInvalidationScratch::default();
    impacted_entries_into(
        intervention_mask,
        rule_adj,
        state,
        join_rules,
        n,
        max_iterations,
        lineage_cells,
        &mut out,
        &mut scratch,
    );
    out
}

#[cfg(all(test, feature = "self-substrate-adapters"))]
mod tests {
    use super::*;

    #[test]
    fn impact_mask_marks_lineage_intersection() {
        let n = 3;
        let mut rule_adj = vec![0u32; 9];
        rule_adj[0 * 3 + 1] = 1;
        let intervention_mask = vec![1, 0, 0];

        let mut state = vec![0u32; 9];
        state[1 * 3] = 1;
        let join_rules = vec![0u32; 9];
        let mask = impacted_entries(
            &intervention_mask,
            &rule_adj,
            &state,
            &join_rules,
            n,
            16,
            &[1, 2],
        );
        assert_eq!(mask, vec![1, 0]);
    }

    #[test]
    fn malformed_dimensions_do_not_panic() {
        let mask = impacted_entries(&[1], &[], &[], &[], 32, 16, &[0, 1]);
        assert_eq!(mask, vec![0, 0]);
    }
}
