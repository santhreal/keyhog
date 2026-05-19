//! Fusion-subset selection used by megakernel batch dispatchers.
//!
//! This runtime path is deliberately self-contained: it does not call
//! self-substrate CPU reference solvers while preparing megakernel work.

use super::MegakernelWorkItem;

mod prologue;
pub use prologue::shared_prologue_length;

/// Reusable buffers for megakernel fusion-subset selection.
///
/// Runtime schedulers can keep one scratch object per worker and avoid
/// allocating the homotopy, seed, flow, and result buffers every batch.
#[derive(Debug, Default)]
pub struct FusionSelectionScratch {
    order: Vec<usize>,
    result: Vec<u32>,
    conflict_degrees: Vec<u32>,
    conflict_masks: Vec<u64>,
    selected_chunks: Vec<u64>,
}

impl FusionSelectionScratch {
    /// Selected 0/1 fusion vector from the last selector invocation.
    #[must_use]
    pub fn result(&self) -> &[u32] {
        &self.result
    }

    /// Move out the current result while retaining the other scratch buffers.
    #[must_use]
    pub fn take_result(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.result)
    }

    fn prepare(&mut self, n: usize) {
        self.order.clear();
        self.order.extend(0..n);
        self.result.clear();
        self.result.resize(n, 0);
        self.conflict_degrees.clear();
        self.conflict_degrees.resize(n, 0);
        self.conflict_masks.clear();
        self.selected_chunks.clear();
    }
}

/// Input-shape error from megakernel fusion subset selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FusionSelectionError {
    /// `n * n` overflowed `usize`.
    ExchangeSizeOverflow {
        /// Requested item count.
        n: usize,
    },
    /// Cost vector length did not match `n`.
    CostLen {
        /// Expected number of costs.
        expected: usize,
        /// Actual number of costs.
        actual: usize,
    },
    /// Exchange adjacency length did not match `n * n`.
    ExchangeAdjLen {
        /// Expected number of row-major adjacency cells.
        expected: usize,
        /// Actual number of adjacency cells.
        actual: usize,
    },
}

impl std::fmt::Display for FusionSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExchangeSizeOverflow { n } => write!(
                f,
                "megakernel fusion selector n*n overflow for n={n}. Fix: shard the work batch before fusion selection."
            ),
            Self::CostLen { expected, actual } => write!(
                f,
                "megakernel fusion selector cost length {actual} does not match n={expected}. Fix: pass one cost per work item."
            ),
            Self::ExchangeAdjLen { expected, actual } => write!(
                f,
                "megakernel fusion selector exchange_adj length {actual} does not match n*n={expected}. Fix: pass a dense row-major n*n exchange graph."
            ),
        }
    }
}

impl std::error::Error for FusionSelectionError {}

fn validate_selector_shape(
    cost_len: usize,
    n: u32,
    exchange_adj_len: usize,
) -> Result<(usize, usize), FusionSelectionError> {
    let n_usize = n as usize;
    let cells = n_usize
        .checked_mul(n_usize)
        .ok_or(FusionSelectionError::ExchangeSizeOverflow { n: n_usize })?;
    if cost_len != n_usize {
        return Err(FusionSelectionError::CostLen {
            expected: n_usize,
            actual: cost_len,
        });
    }
    if exchange_adj_len != cells {
        return Err(FusionSelectionError::ExchangeAdjLen {
            expected: cells,
            actual: exchange_adj_len,
        });
    }
    Ok((n_usize, cells))
}

/// Reusable scratch for compact runtime fusion planning.
///
/// Concrete drivers own command submission. Runtime owns the queue-shaping
/// policy: cost seeds, divergence flags, exchange graph, and selector output.
#[derive(Debug, Default)]
pub struct CompactFusionPlanningScratch {
    costs_q16: Vec<u16>,
    stalks: Vec<f32>,
    diffused_stalks: Vec<f32>,
    effective_divergence: Vec<u32>,
    deltas: Vec<f32>,
    sorted_deltas: Vec<f32>,
    exchange_adj: Vec<u32>,
    selection: FusionSelectionScratch,
}

impl CompactFusionPlanningScratch {
    /// Last exchange adjacency matrix, row-major `n*n`.
    #[must_use]
    pub fn exchange_adj(&self) -> &[u32] {
        &self.exchange_adj
    }

    /// Last 0/1 selection vector.
    #[must_use]
    pub fn selected(&self) -> &[u32] {
        self.selection.result()
    }
}

/// Build the compact megakernel fusion plan for one work batch.
///
/// Returns the selector's 0/1 keep vector. The matching exchange adjacency is
/// retained in `scratch.exchange_adj()` for provenance and diagnostics.
pub fn plan_compact_fusion_into<'a>(
    work_items: &[MegakernelWorkItem],
    scratch: &'a mut CompactFusionPlanningScratch,
) -> &'a [u32] {
    let n = work_items.len();
    if n == 0 {
        scratch.costs_q16.clear();
        scratch.stalks.clear();
        scratch.diffused_stalks.clear();
        scratch.effective_divergence.clear();
        scratch.deltas.clear();
        scratch.sorted_deltas.clear();
        scratch.exchange_adj.clear();
        scratch.selection.prepare(0);
        return scratch.selection.result();
    }

    scratch.costs_q16.clear();
    scratch.costs_q16.resize(n, u16::MAX);
    if n <= 32 {
        for i in 0..n {
            for j in 0..n {
                if i != j && work_items[i].op_handle == work_items[j].op_handle {
                    scratch.costs_q16[i] = scratch.costs_q16[i].saturating_sub(3_276);
                }
            }
        }
    }

    scratch.stalks.clear();
    scratch.stalks.extend(
        work_items
            .iter()
            .map(|item| (item.op_handle as f32) * 0.001),
    );
    scratch.diffused_stalks.clear();
    scratch.diffused_stalks.extend_from_slice(&scratch.stalks);
    for _ in 0..8 {
        for value in &mut scratch.diffused_stalks {
            *value -= 0.5_f32 * 0.7_f32 * *value;
        }
    }

    let divergence_threshold = 0.05_f32;
    scratch.effective_divergence.clear();
    scratch.effective_divergence.extend(
        scratch
            .stalks
            .iter()
            .zip(scratch.diffused_stalks.iter())
            .map(|(&initial, &diffused)| {
                u32::from((initial - diffused).abs() > divergence_threshold)
            }),
    );

    let gap_signal = 1.0_f32;
    if gap_signal < 0.3 {
        scratch.deltas.clear();
        scratch.deltas.extend(
            scratch
                .stalks
                .iter()
                .zip(scratch.diffused_stalks.iter())
                .map(|(s, d)| (s - d).abs()),
        );
        scratch.sorted_deltas.clear();
        scratch.sorted_deltas.extend_from_slice(&scratch.deltas);
        scratch
            .sorted_deltas
            .sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = scratch
            .sorted_deltas
            .get(scratch.sorted_deltas.len() / 2)
            .copied()
            .unwrap_or(0.0);
        for (flag, delta) in scratch
            .effective_divergence
            .iter_mut()
            .zip(scratch.deltas.iter())
        {
            if *delta < median {
                *flag = 0;
            }
        }
    }

    scratch.exchange_adj.clear();
    scratch.exchange_adj.resize(n.saturating_mul(n), 0);
    for i in 0..n {
        let row_start = i * n;
        for j in 0..n {
            if i == j {
                continue;
            }
            let same_op = work_items[i].op_handle == work_items[j].op_handle;
            let stalk_drift =
                scratch.effective_divergence[i] != 0 && scratch.effective_divergence[j] != 0;
            if same_op || stalk_drift {
                scratch.exchange_adj[row_start + j] = 1;
            }
        }
    }
    if (0..n.saturating_sub(1)).any(|i| {
        work_items.get(i).map(|w| w.output_handle) == work_items.get(i + 1).map(|w| w.input_handle)
    }) {
        for cost in scratch.costs_q16.iter_mut() {
            *cost = cost.saturating_sub(3_276);
        }
    }

    select_fused_subset_compact_into(
        &scratch.costs_q16,
        n as u32,
        &scratch.exchange_adj,
        &mut scratch.selection,
    );
    scratch.selection.result()
}

/// Compute a deterministic maximal fusion subset for a batch of megakernel work items.
///
/// `costs[i]` is the dispatch cost of program `i` (lower is cheaper).
/// `exchange_adj[i*n+j]` is non-zero when fusing `i` and `j` is
/// incompatible (memory overflow, sync class boundary, etc.).
///
/// Returns a 0/1 selection vector of length `n`.
#[must_use]
pub fn select_fused_subset(costs: &[f64], n: u32, exchange_adj: &[u32]) -> Vec<u32> {
    let mut scratch = FusionSelectionScratch::default();
    select_fused_subset_into(costs, n, exchange_adj, &mut scratch);
    scratch.take_result()
}

/// Compute the optimal fusion subset into reusable scratch buffers.
pub fn select_fused_subset_into(
    costs: &[f64],
    n: u32,
    exchange_adj: &[u32],
    scratch: &mut FusionSelectionScratch,
) {
    if select_fused_subset_checked_into(costs, n, exchange_adj, scratch).is_err() {
        scratch.result.clear();
        scratch.order.clear();
    }
}

/// Checked selector variant that reports malformed planner input.
pub fn select_fused_subset_checked_into(
    costs: &[f64],
    n: u32,
    exchange_adj: &[u32],
    scratch: &mut FusionSelectionScratch,
) -> Result<(), FusionSelectionError> {
    let (n_usize, _cells) = validate_selector_shape(costs.len(), n, exchange_adj.len())?;
    scratch.prepare(n_usize);
    compute_conflict_degrees(exchange_adj, n_usize, &mut scratch.conflict_degrees);
    scratch.order.sort_unstable_by(|&a, &b| {
        costs[a]
            .total_cmp(&costs[b])
            .then_with(|| scratch.conflict_degrees[a].cmp(&scratch.conflict_degrees[b]))
            .then_with(|| a.cmp(&b))
    });
    select_ordered_maximal(
        exchange_adj,
        n_usize,
        &scratch.order,
        &mut scratch.conflict_masks,
        &mut scratch.selected_chunks,
        &mut scratch.result,
    );
    Ok(())
}

/// Compact-cost selector for hot runtime dispatchers.
///
/// `costs_q16[i]` is a normalized fixed-point dispatch cost where lower is
/// cheaper. This avoids carrying `Vec<f64>` scratch through runtime hot paths;
/// the exact matroid rounder still receives the same exchange graph.
#[must_use]
pub fn select_fused_subset_compact(costs_q16: &[u16], n: u32, exchange_adj: &[u32]) -> Vec<u32> {
    let mut scratch = FusionSelectionScratch::default();
    select_fused_subset_compact_into(costs_q16, n, exchange_adj, &mut scratch);
    scratch.take_result()
}

/// Compact-cost selector using caller-owned scratch buffers.
pub fn select_fused_subset_compact_into(
    costs_q16: &[u16],
    n: u32,
    exchange_adj: &[u32],
    scratch: &mut FusionSelectionScratch,
) {
    if select_fused_subset_compact_checked_into(costs_q16, n, exchange_adj, scratch).is_err() {
        scratch.result.clear();
        scratch.order.clear();
    }
}

/// Checked compact selector variant that reports malformed planner input.
pub fn select_fused_subset_compact_checked_into(
    costs_q16: &[u16],
    n: u32,
    exchange_adj: &[u32],
    scratch: &mut FusionSelectionScratch,
) -> Result<(), FusionSelectionError> {
    let (n_usize, _cells) = validate_selector_shape(costs_q16.len(), n, exchange_adj.len())?;
    scratch.prepare(n_usize);
    compute_conflict_degrees(exchange_adj, n_usize, &mut scratch.conflict_degrees);
    scratch.order.sort_unstable_by(|&a, &b| {
        costs_q16[a]
            .cmp(&costs_q16[b])
            .then_with(|| scratch.conflict_degrees[a].cmp(&scratch.conflict_degrees[b]))
            .then_with(|| a.cmp(&b))
    });
    select_ordered_maximal(
        exchange_adj,
        n_usize,
        &scratch.order,
        &mut scratch.conflict_masks,
        &mut scratch.selected_chunks,
        &mut scratch.result,
    );
    Ok(())
}

/// Compute a cost-ordered maximal fusion subset with the same output contract
/// as [`select_fused_subset`].
#[must_use]
pub fn select_optimal_fused_subset(costs: &[f64], n: u32, exchange_adj: &[u32]) -> Vec<u32> {
    select_fused_subset(costs, n, exchange_adj)
}

/// Runtime-compatible selector entry point that preserves the historical API.
#[must_use]
pub fn select_fused_subset_with_rate(costs: &[f64], n: u32, exchange_adj: &[u32]) -> Vec<u32> {
    select_fused_subset(costs, n, exchange_adj)
}

/// Select a cost-ordered fused subset, then eliminate arms whose gate
/// predicates have already proven them to be no-ops for this dispatch.
///
/// This is the runtime-facing C5 entry point: it keeps the historical
/// selection algorithm unchanged, then applies [`prune_dead_arms_inplace`]
/// before the caller materializes the launch sequence.
#[must_use]
pub fn select_fused_subset_pruned(
    costs: &[f64],
    n: u32,
    exchange_adj: &[u32],
    dead_mask: &[bool],
) -> Vec<u32> {
    let mut selection = select_fused_subset(costs, n, exchange_adj);
    prune_dead_arms_inplace(&mut selection, dead_mask);
    selection
}

/// Reusable-scratch variant of [`select_fused_subset_pruned`].
pub fn select_fused_subset_pruned_into(
    costs: &[f64],
    n: u32,
    exchange_adj: &[u32],
    dead_mask: &[bool],
    scratch: &mut FusionSelectionScratch,
) {
    select_fused_subset_into(costs, n, exchange_adj, scratch);
    prune_dead_arms_inplace(&mut scratch.result, dead_mask);
}

/// ROADMAP C5 substrate: gated no-op middle-arm elimination.
///
/// Given a `selection` 0/1 vector (one entry per arm in the megakernel
/// dispatch sequence) and a `dead_mask` of the same length where
/// `dead_mask[i] = true` means arm `i` has been proven to be a no-op
/// at this dispatch (gate predicate folds to false, output equals
/// input, etc.), zero out the corresponding selection entries in
/// place. Returns the number of arms eliminated so the caller can
/// log/telemeter the win.
///
/// Length mismatch returns `0` and leaves the selection untouched —
/// the caller is responsible for passing matching slices. The
/// substrate is pure: it does not allocate, panic, or call into any
/// other planner subsystem; the dispatcher consumes the modified
/// selection unchanged.
///
/// Example: an inference megakernel where arm 1 is a `mask × value`
/// step that's gated `mask != 0`. If the static analyzer proves the
/// mask buffer is all-zero for this batch, dispatch can elide arm 1
/// entirely. Without this elision the GPU launches a full kernel that
/// reads both buffers, computes the multiplication, and writes a
/// zero-result back — pure waste.
pub fn prune_dead_arms_inplace(selection: &mut [u32], dead_mask: &[bool]) -> u32 {
    if selection.len() != dead_mask.len() {
        return 0;
    }
    let mut eliminated = 0_u32;
    for (slot, &dead) in selection.iter_mut().zip(dead_mask.iter()) {
        if dead && *slot != 0 {
            *slot = 0;
            eliminated = eliminated.saturating_add(1);
        }
    }
    eliminated
}

fn compute_conflict_degrees(exchange_adj: &[u32], n: usize, out: &mut [u32]) {
    debug_assert_eq!(out.len(), n);
    out.fill(0);
    for i in 0..n {
        let row = i * n;
        for j in (i + 1)..n {
            if exchange_adj[row + j] != 0 || exchange_adj[j * n + i] != 0 {
                out[i] = out[i].saturating_add(1);
                out[j] = out[j].saturating_add(1);
            }
        }
    }
}

fn compatible_with_selection(exchange_adj: &[u32], n: usize, result: &[u32], item: usize) -> bool {
    for selected in 0..n {
        if result[selected] == 0 {
            continue;
        }
        if exchange_adj[item * n + selected] != 0 || exchange_adj[selected * n + item] != 0 {
            return false;
        }
    }
    true
}

fn select_ordered_maximal(
    exchange_adj: &[u32],
    n: usize,
    order: &[usize],
    conflict_masks: &mut Vec<u64>,
    selected_chunks: &mut Vec<u64>,
    result: &mut [u32],
) {
    result.fill(0);
    if n <= 256 {
        for &item in order {
            if item < n && compatible_with_selection(exchange_adj, n, result, item) {
                result[item] = 1;
            }
        }
        return;
    }

    let words = n.div_ceil(64);
    conflict_masks.clear();
    let needed_masks = words.checked_mul(n).unwrap_or(0);
    conflict_masks.resize(needed_masks, 0);
    for i in 0..n {
        let row_start = i * n;
        for j in (i + 1)..n {
            if exchange_adj[row_start + j] == 0 && exchange_adj[j * n + i] == 0 {
                continue;
            }
            let j_word = j / 64;
            let j_bit = j % 64;
            conflict_masks[i * words + j_word] |= 1_u64 << j_bit;

            let i_word = i / 64;
            let i_bit = i % 64;
            conflict_masks[j * words + i_word] |= 1_u64 << i_bit;
        }
    }

    selected_chunks.clear();
    selected_chunks.resize(words, 0);
    for &item in order {
        if item >= n {
            continue;
        }
        let mut conflicted = false;
        let base = item * words;
        for chunk_idx in 0..words {
            if (conflict_masks[base + chunk_idx] & selected_chunks[chunk_idx]) != 0 {
                conflicted = true;
                break;
            }
        }
        if !conflicted {
            result[item] = 1;
            let word = item / 64;
            selected_chunks[word] |= 1_u64 << (item % 64);
        }
    }
}

#[cfg(test)]
mod tests;
