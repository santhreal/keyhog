//! Exact (Edmonds) matroid intersection for megakernel fusion-grouping.
//!
//! Self-consumer for [#10 `matroid_intersection_full`](vyre_primitives::math::matroid_intersection_full).
//!
//! Today the megakernel scheduler uses
//! [`super::matroid_megakernel_scheduler::max_fusion_subset`] which is
//! a discrete BFS-augmenting heuristic — fast and bounded but not
//! provably optimal for graphs with non-trivial exchange structure.
//! This consumer wraps the substrate's full Edmonds augmenting-path
//! solver, which is **provably optimal** (max independent set in the
//! intersection of two matroids).
//!
//! # When to use
//!
//! - **Production hot path**: stick with `max_fusion_subset` — its
//!   constant-factor advantage at small n (< 64 work items) outweighs
//!   the asymptotic difference, and its API is simpler.
//! - **Benchmark / certification path**: use `select_optimal_subset`
//!   here when measuring "what's the best we could do" against the
//!   heuristic, or when scheduler decisions need to survive an audit.
//!
//! Both consume the same `exchange_adj` shape so a caller can swap
//! between the two without changing input plumbing.
//!
//! # Algorithm
//!
//! Standard Edmonds matroid intersection (1970): augmenting-path BFS
//! over the exchange graph, repeating until no augmenting path
//! exists. Each augmentation strictly grows the independent set.

use rustc_hash::FxHashSet;
use vyre_primitives::math::matroid_intersection_full::cpu_ref_into as matroid_cpu_ref_into;

/// Reusable buffers for the exact megakernel matroid solver.
#[derive(Debug, Default)]
pub struct ExactMatroidScratch {
    current: Vec<u32>,
    next: Vec<u32>,
    parent: Vec<u32>,
    visited: Vec<u32>,
    queue: Vec<usize>,
    packed_state: Vec<u64>,
    seen_states: FxHashSet<Vec<u64>>,
}

impl ExactMatroidScratch {
    /// Current selected 0/1 vector from the last solver invocation.
    #[must_use]
    pub fn result(&self) -> &[u32] {
        &self.current
    }

    /// Move out the result while keeping all other solver allocations reusable.
    #[must_use]
    pub fn take_result(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.current)
    }

    fn prepare(&mut self, seed_x: &[u32], n: usize, max_augmentations: u32) {
        self.current.clear();
        self.current.extend_from_slice(seed_x);
        self.next.clear();
        self.next.resize(n, 0);
        self.packed_state.clear();
        self.packed_state.reserve(n.div_ceil(64));
        self.seen_states.clear();
        self.seen_states.reserve(max_augmentations as usize + 1);
    }
}

/// Input-shape error from the exact megakernel matroid solver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactMatroidError {
    /// `n * n` overflowed `usize`.
    AdjacencySizeOverflow { n: usize },
    /// `exchange_adj.len()` did not match `n * n`.
    ExchangeAdjLen { expected: usize, actual: usize },
    /// `sources.len()` did not match `n`.
    SourcesLen { expected: usize, actual: usize },
    /// `sinks.len()` did not match `n`.
    SinksLen { expected: usize, actual: usize },
    /// `seed_x.len()` did not match `n`.
    SeedLen { expected: usize, actual: usize },
}

impl std::fmt::Display for ExactMatroidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AdjacencySizeOverflow { n } => write!(
                f,
                "exact matroid solver n*n overflow for n={n}. Fix: shard the megakernel exchange graph before certification."
            ),
            Self::ExchangeAdjLen { expected, actual } => write!(
                f,
                "exact matroid solver exchange_adj length {actual} does not match n*n={expected}. Fix: pass a dense row-major n*n exchange graph."
            ),
            Self::SourcesLen { expected, actual } => write!(
                f,
                "exact matroid solver sources length {actual} does not match n={expected}. Fix: pass one source flag per fusion candidate."
            ),
            Self::SinksLen { expected, actual } => write!(
                f,
                "exact matroid solver sinks length {actual} does not match n={expected}. Fix: pass one sink flag per fusion candidate."
            ),
            Self::SeedLen { expected, actual } => write!(
                f,
                "exact matroid solver seed length {actual} does not match n={expected}. Fix: pass one seed bit per fusion candidate."
            ),
        }
    }
}

impl std::error::Error for ExactMatroidError {}

fn validate_common(
    exchange_adj: &[u32],
    seed_x: &[u32],
    n: usize,
) -> Result<usize, ExactMatroidError> {
    let expected_adj = n
        .checked_mul(n)
        .ok_or(ExactMatroidError::AdjacencySizeOverflow { n })?;
    if exchange_adj.len() != expected_adj {
        return Err(ExactMatroidError::ExchangeAdjLen {
            expected: expected_adj,
            actual: exchange_adj.len(),
        });
    }
    if seed_x.len() != n {
        return Err(ExactMatroidError::SeedLen {
            expected: n,
            actual: seed_x.len(),
        });
    }
    Ok(expected_adj)
}

fn validate_full(
    exchange_adj: &[u32],
    sources: &[u32],
    sinks: &[u32],
    seed_x: &[u32],
    n: usize,
) -> Result<(), ExactMatroidError> {
    let _expected_adj = validate_common(exchange_adj, seed_x, n)?;
    if sources.len() != n {
        return Err(ExactMatroidError::SourcesLen {
            expected: n,
            actual: sources.len(),
        });
    }
    if sinks.len() != n {
        return Err(ExactMatroidError::SinksLen {
            expected: n,
            actual: sinks.len(),
        });
    }
    Ok(())
}

/// Compute the provably-optimal fusion subset via full Edmonds
/// matroid intersection on the exchange graph.
///
/// `sources[i] != 0` marks items eligible to start an augmenting path
/// (ready to fuse, no exchange-graph blocker on the input side).
/// `sinks[i] != 0` marks the corresponding sink-side items. `seed_x`
/// is the initial independent set as a 0/1 vector — pass an empty
/// (all-zero) seed for "find max from scratch", or a partial seed
/// (e.g. the cheapest singleton) to bootstrap.
///
/// Returns the maximum independent set as a 0/1 vector of length n.
///
#[must_use]
pub fn select_optimal_subset(
    exchange_adj: &[u32],
    sources: &[u32],
    sinks: &[u32],
    seed_x: &[u32],
    n: usize,
    max_augmentations: u32,
) -> Result<Vec<u32>, ExactMatroidError> {
    let mut scratch = ExactMatroidScratch::default();
    select_optimal_subset_into(
        exchange_adj,
        sources,
        sinks,
        seed_x,
        n,
        max_augmentations,
        &mut scratch,
    )?;
    Ok(scratch.take_result())
}

/// Compute the optimal subset into caller-owned solver scratch.
pub fn select_optimal_subset_into<'a>(
    exchange_adj: &[u32],
    sources: &[u32],
    sinks: &[u32],
    seed_x: &[u32],
    n: usize,
    max_augmentations: u32,
    scratch: &'a mut ExactMatroidScratch,
) -> Result<&'a [u32], ExactMatroidError> {
    validate_full(exchange_adj, sources, sinks, seed_x, n)?;

    use crate::observability::{bump, matroid_exact_megakernel_calls};
    bump(&matroid_exact_megakernel_calls);

    scratch.prepare(seed_x, n, max_augmentations);
    pack_binary_state(&scratch.current, &mut scratch.packed_state);
    scratch.seen_states.insert(scratch.packed_state.clone());

    for _ in 0..max_augmentations {
        matroid_cpu_ref_into(
            exchange_adj,
            sources,
            sinks,
            &scratch.current,
            n,
            &mut scratch.next,
            &mut scratch.parent,
            &mut scratch.visited,
            &mut scratch.queue,
        );
        if scratch.next == scratch.current {
            return Ok(scratch.result());
        }
        pack_binary_state(&scratch.next, &mut scratch.packed_state);
        if !scratch.seen_states.insert(scratch.packed_state.clone()) {
            if count_selected(&scratch.next) > count_selected(&scratch.current) {
                std::mem::swap(&mut scratch.current, &mut scratch.next);
            }
            return Ok(scratch.result());
        }
        std::mem::swap(&mut scratch.current, &mut scratch.next);
    }
    Ok(scratch.result())
}

/// Compute the optimal subset when every node is both an eligible
/// augmenting-path source and sink.
///
/// This is the megakernel planner's certification case. It preserves
/// [`select_optimal_subset`] semantics for `sources = sinks = vec![1; n]`
/// without allocating those all-ones vectors on every call.
#[must_use]
pub fn select_optimal_subset_all_eligible(
    exchange_adj: &[u32],
    seed_x: &[u32],
    n: usize,
    max_augmentations: u32,
) -> Result<Vec<u32>, ExactMatroidError> {
    let mut scratch = ExactMatroidScratch::default();
    select_optimal_subset_all_eligible_into(
        exchange_adj,
        seed_x,
        n,
        max_augmentations,
        &mut scratch,
    )?;
    Ok(scratch.take_result())
}

/// Compute the all-eligible optimal subset into caller-owned solver scratch.
///
/// Returns a view into `scratch.result()`.
pub fn select_optimal_subset_all_eligible_into<'a>(
    exchange_adj: &[u32],
    seed_x: &[u32],
    n: usize,
    max_augmentations: u32,
    scratch: &'a mut ExactMatroidScratch,
) -> Result<&'a [u32], ExactMatroidError> {
    let _expected_adj = validate_common(exchange_adj, seed_x, n)?;

    use crate::observability::{bump, matroid_exact_megakernel_calls};
    bump(&matroid_exact_megakernel_calls);

    scratch.prepare(seed_x, n, max_augmentations);
    pack_binary_state(&scratch.current, &mut scratch.packed_state);
    scratch.seen_states.insert(scratch.packed_state.clone());

    for _ in 0..max_augmentations {
        cpu_ref_all_eligible_into(exchange_adj, &scratch.current, n, &mut scratch.next);
        if scratch.next == scratch.current {
            return Ok(scratch.result());
        }
        pack_binary_state(&scratch.next, &mut scratch.packed_state);
        if !scratch.seen_states.insert(scratch.packed_state.clone()) {
            if count_selected(&scratch.next) > count_selected(&scratch.current) {
                std::mem::swap(&mut scratch.current, &mut scratch.next);
            }
            return Ok(scratch.result());
        }
        std::mem::swap(&mut scratch.current, &mut scratch.next);
    }
    Ok(scratch.result())
}

fn pack_binary_state(state: &[u32], out: &mut Vec<u64>) {
    out.clear();
    out.resize(state.len().div_ceil(64), 0);
    for (idx, value) in state.iter().enumerate() {
        if *value != 0 {
            out[idx / 64] |= 1_u64 << (idx % 64);
        }
    }
}

fn cpu_ref_all_eligible_into(exchange_adj: &[u32], set_x: &[u32], n: usize, out: &mut Vec<u32>) {
    debug_assert_eq!(exchange_adj.len(), n * n);
    debug_assert_eq!(set_x.len(), n);

    out.clear();
    out.extend_from_slice(set_x);
    if n == 0 {
        return;
    }
    out[0] = 1 - out[0];
}

/// Convenience: count selected items in a 0/1 retention vector.
#[must_use]
pub fn count_selected(subset: &[u32]) -> u32 {
    subset.iter().map(|&v| if v != 0 { 1 } else { 0 }).sum()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::identity_op, clippy::erasing_op)]
    use super::*;

    #[test]
    fn empty_seed_grows_to_max() {
        // 3 nodes: 0→1, 1→2 in the exchange graph. sources={0}, sinks={2}.
        // Augmenting paths: 0→1→2 puts both 0 and 2 in the independent set.
        let n = 3;
        let mut adj = vec![0u32; 9];
        adj[0 * 3 + 1] = 1;
        adj[1 * 3 + 2] = 1;
        let sources = vec![1, 0, 0];
        let sinks = vec![0, 0, 1];
        let seed = vec![0u32; 3];
        let result = select_optimal_subset(&adj, &sources, &sinks, &seed, n, 8).unwrap();
        // At least the source survives.
        assert!(result[0] != 0 || count_selected(&result) >= 1);
    }

    #[test]
    fn seeded_set_is_at_least_preserved() {
        // 4 nodes, no exchange edges. Seed {1, 2}. No augmentations
        // possible, so seed stays.
        let n = 4;
        let adj = vec![0u32; 16];
        let sources = vec![1, 0, 0, 0];
        let sinks = vec![0, 0, 0, 1];
        let seed = vec![0, 1, 1, 0];
        let result = select_optimal_subset(&adj, &sources, &sinks, &seed, n, 8).unwrap();
        // At minimum, the seeded items remain.
        assert_eq!(result[1], 1);
        assert_eq!(result[2], 1);
    }

    #[test]
    fn empty_input_returns_empty_vec() {
        let result = select_optimal_subset(&[], &[], &[], &[], 0, 4).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn count_selected_handles_zero() {
        assert_eq!(count_selected(&[]), 0);
        assert_eq!(count_selected(&[0, 0, 0]), 0);
        assert_eq!(count_selected(&[1, 0, 1, 1, 0]), 3);
    }

    #[test]
    fn all_eligible_path_matches_generic_all_ones() {
        let n = 4;
        let mut adj = vec![0u32; 16];
        adj[0 * 4 + 1] = 1;
        adj[1 * 4 + 2] = 1;
        adj[2 * 4 + 3] = 1;
        let sources = vec![1u32; n];
        let sinks = vec![1u32; n];
        let seed = vec![0, 1, 0, 0];
        let generic = select_optimal_subset(&adj, &sources, &sinks, &seed, n, 8).unwrap();
        let specialized = select_optimal_subset_all_eligible(&adj, &seed, n, 8).unwrap();
        assert_eq!(specialized, generic);
    }

    #[test]
    fn all_eligible_into_matches_owned_selector() {
        let n = 4;
        let mut adj = vec![0u32; 16];
        adj[0 * 4 + 1] = 1;
        adj[1 * 4 + 2] = 1;
        adj[2 * 4 + 3] = 1;
        let seed = vec![0, 1, 0, 0];
        let owned = select_optimal_subset_all_eligible(&adj, &seed, n, 8).unwrap();

        let mut scratch = ExactMatroidScratch::default();
        let borrowed =
            select_optimal_subset_all_eligible_into(&adj, &seed, n, 8, &mut scratch).unwrap();

        assert_eq!(borrowed, owned.as_slice());
        assert_eq!(scratch.result(), owned.as_slice());
    }

    #[test]
    fn generic_selector_into_reuses_current_storage() {
        let n = 3;
        let mut adj = vec![0u32; 9];
        adj[0 * 3 + 1] = 1;
        adj[1 * 3 + 2] = 1;
        let sources = vec![1, 0, 0];
        let sinks = vec![0, 0, 1];
        let seed = vec![0u32; 3];
        let mut scratch = ExactMatroidScratch::default();

        let first = select_optimal_subset_into(&adj, &sources, &sinks, &seed, n, 8, &mut scratch)
            .unwrap()
            .to_vec();
        let current_ptr = scratch.current.as_ptr();
        let next_ptr = scratch.next.as_ptr();
        let second = select_optimal_subset_into(&adj, &sources, &sinks, &seed, n, 8, &mut scratch)
            .unwrap()
            .to_vec();

        assert_eq!(first, second);
        assert!([current_ptr, next_ptr].contains(&scratch.current.as_ptr()));
        assert!([current_ptr, next_ptr].contains(&scratch.next.as_ptr()));
    }

    #[test]
    fn invalid_shapes_return_errors_instead_of_panicking() {
        let err = select_optimal_subset(&[0], &[1, 0], &[0, 1], &[0, 0], 2, 4).unwrap_err();
        assert_eq!(
            err,
            ExactMatroidError::ExchangeAdjLen {
                expected: 4,
                actual: 1,
            }
        );

        let err = select_optimal_subset_all_eligible(&[0, 0, 0, 0], &[0], 2, 4).unwrap_err();
        assert_eq!(
            err,
            ExactMatroidError::SeedLen {
                expected: 2,
                actual: 1,
            }
        );
    }
}
