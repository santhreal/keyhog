//! Region-graph dataflow fixpoint via #1 `semiring_gemm` (#26 substrate).
//!
//! Treats vyre's Region tree adjacency as a sparse boolean matrix
//! and computes reachability / liveness / dominance / constant-prop
//! via `semiring_gemm` iterations under different semirings:
//!
//! | Analysis | Semiring | Combine | Accumulate |
//! |---|---|---|---|
//! | Reachability | `BoolOr` | AND | OR |
//! | Liveness | `BoolOr` (reverse direction) | AND | OR |
//! | Reaching defs | `Lineage` | OR (zero-absorbing) | OR |
//! | Constant prop | `Lineage` | OR | OR |
//! | Min-cost path | `MinPlus` | + (sat) | min |
//!
//! Same primitive (#1), same Program, four different IR analyses.
//! Demonstrates the recursion thesis directly.

pub use vyre_spec::Semiring;

/// Multiply matrices over the selected semiring on the CPU.
#[must_use]
pub fn semiring_gemm_cpu(
    left: &[u32],
    right: &[u32],
    rows: u32,
    cols: u32,
    inner: u32,
    semiring: Semiring,
) -> Vec<u32> {
    let Some(out_len) = rows.checked_mul(cols).map(|v| v as usize) else {
        return Vec::new();
    };
    let Some(left_len) = rows.checked_mul(inner).map(|v| v as usize) else {
        return Vec::new();
    };
    let Some(right_len) = inner.checked_mul(cols).map(|v| v as usize) else {
        return Vec::new();
    };
    if left.len() < left_len || right.len() < right_len {
        return Vec::new();
    }
    let mut output = vec![semiring.identity(); out_len];
    let rows = rows as usize;
    let cols = cols as usize;
    let inner = inner as usize;
    for row in 0..rows {
        for col in 0..cols {
            let mut acc = semiring.identity();
            for scan in 0..inner {
                let left_value = left[row * inner + scan];
                let right_value = right[scan * cols + col];

                let combined = match semiring {
                    Semiring::Real | Semiring::MaxTimes => left_value.wrapping_mul(right_value),
                    Semiring::MinPlus => {
                        if left_value == u32::MAX || right_value == u32::MAX {
                            u32::MAX
                        } else {
                            left_value.saturating_add(right_value)
                        }
                    }
                    Semiring::MaxPlus => left_value.saturating_add(right_value),
                    Semiring::BoolOr | Semiring::Gf2 => left_value & right_value,
                    Semiring::BoolAnd => left_value | right_value,
                    Semiring::Lineage => {
                        if left_value == 0 || right_value == 0 {
                            0
                        } else {
                            left_value | right_value
                        }
                    }
                };

                acc = match semiring {
                    Semiring::Real | Semiring::MaxPlus => acc.wrapping_add(combined),
                    Semiring::MinPlus => acc.min(combined),
                    Semiring::MaxTimes => acc.max(combined),
                    Semiring::BoolOr | Semiring::Lineage => acc | combined,
                    Semiring::BoolAnd => acc & combined,
                    Semiring::Gf2 => acc ^ combined,
                };
            }
            output[row * cols + col] = acc;
        }
    }
    output
}

fn square_cells(n: u32) -> Option<usize> {
    n.checked_mul(n).map(|cells| cells as usize)
}

/// Compute boolean reachability closure on a Region adjacency matrix
/// via repeated `semiring_gemm` iterations under `Semiring::BoolOr`.
/// Iterates until fixpoint (max `max_iters` steps).
#[must_use]
pub fn reachability_closure(adj: &[u32], n: u32, max_iters: u32) -> Vec<u32> {
    let Some(cells) = square_cells(n) else {
        return Vec::new();
    };
    if n == 0 || adj.len() != cells {
        return Vec::new();
    }
    let mut current = adj.to_vec();
    for _ in 0..max_iters {
        let next = semiring_gemm_cpu(&current, &current, n, n, n, Semiring::BoolOr);
        // Union with self for transitive-reflexive closure.
        let unioned: Vec<u32> = current
            .iter()
            .zip(next.iter())
            .map(|(&a, &b)| a | b)
            .collect();
        if unioned == current {
            return unioned;
        }
        current = unioned;
    }
    current
}

/// Compute lineage (which-clauses-used) closure under `Semiring::Lineage`.
/// Each entry of `adj` is a bitset of clause/source IDs.
#[must_use]
pub fn lineage_closure(adj: &[u32], n: u32, max_iters: u32) -> Vec<u32> {
    let Some(cells) = square_cells(n) else {
        return Vec::new();
    };
    if n == 0 || adj.len() != cells {
        return Vec::new();
    }
    let mut current = adj.to_vec();
    for _ in 0..max_iters {
        let next = semiring_gemm_cpu(&current, &current, n, n, n, Semiring::Lineage);
        let unioned: Vec<u32> = current
            .iter()
            .zip(next.iter())
            .map(|(&a, &b)| a | b)
            .collect();
        if unioned == current {
            return unioned;
        }
        current = unioned;
    }
    current
}

/// Compute min-cost shortest-path distance matrix under `Semiring::MinPlus`.
/// Use `u32::MAX` for "no edge".
#[must_use]
pub fn shortest_path_closure(adj: &[u32], n: u32, max_iters: u32) -> Vec<u32> {
    let Some(cells) = square_cells(n) else {
        return Vec::new();
    };
    if n == 0 || adj.len() != cells {
        return Vec::new();
    }
    let mut current = adj.to_vec();
    for _ in 0..max_iters {
        let next = semiring_gemm_cpu(&current, &current, n, n, n, Semiring::MinPlus);
        // Take minimum elementwise (one more relaxation step).
        let min_combined: Vec<u32> = current
            .iter()
            .zip(next.iter())
            .map(|(&a, &b)| a.min(b))
            .collect();
        if min_combined == current {
            return min_combined;
        }
        current = min_combined;
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reachability_chain_graph() {
        // 0 → 1 → 2 → 3
        let adj = vec![0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let closure = reachability_closure(&adj, 4, 5);
        // After closure: 0 reaches {1, 2, 3}; 1 reaches {2, 3}; 2 reaches {3}.
        assert_eq!(closure[0 * 4 + 1], 1);
        assert_eq!(closure[0 * 4 + 2], 1);
        assert_eq!(closure[0 * 4 + 3], 1);
        assert_eq!(closure[1 * 4 + 3], 1);
        // No reverse edges
        assert_eq!(closure[3 * 4 + 0], 0);
    }

    #[test]
    fn reachability_disjoint_components_stay_disjoint() {
        // 0 → 1, 2 → 3, no cross.
        let adj = vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let closure = reachability_closure(&adj, 4, 5);
        assert_eq!(closure[0 * 4 + 2], 0);
        assert_eq!(closure[2 * 4 + 0], 0);
    }

    #[test]
    fn lineage_closure_unions_clauses_along_paths() {
        // Edge 0→1 used clause f1 = 0b01; edge 1→2 used clause f2 = 0b10.
        // Path 0→2 uses both: 0b11.
        let f1 = 0b01;
        let f2 = 0b10;
        let adj = vec![0, f1, 0, 0, 0, f2, 0, 0, 0];
        let closure = lineage_closure(&adj, 3, 5);
        assert_eq!(closure[0 * 3 + 2], f1 | f2);
    }

    #[test]
    fn shortest_path_closure_finds_two_hop_minimum() {
        let inf = u32::MAX;
        // 0→1 cost 5, 1→2 cost 3, 0→2 cost 100 (slower direct).
        let adj = vec![inf, 5, 100, inf, inf, 3, inf, inf, inf];
        let closure = shortest_path_closure(&adj, 3, 5);
        // Best 0→2 = min(100, 5+3) = 8.
        assert_eq!(closure[0 * 3 + 2], 8);
    }

    #[test]
    fn reachability_self_loop_detected() {
        // 0 → 1, 1 → 0. Closure should mark both.
        let adj = vec![0, 1, 1, 0];
        let closure = reachability_closure(&adj, 2, 5);
        // After 1 iteration: 0 reaches 0 via 0→1→0; 1 reaches 1.
        assert_eq!(closure[0 * 2 + 0], 1);
        assert_eq!(closure[1 * 2 + 1], 1);
    }
}
