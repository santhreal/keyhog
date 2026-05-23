//! Benchmark-driven CUDA optimization pass selection.
//!
//! Expensive CUDA passes must not fire because a static list says so. They need
//! graph/frontier/reuse evidence showing that the launch, memory, or readback
//! cost they remove is larger than their own planning cost. This module makes
//! that decision explicit and deterministic.

use rustc_hash::FxHashSet;
use std::hash::Hash;

/// One CUDA optimization candidate with benchmark-derived thresholds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaBenchmarkPassCandidate {
    /// Registered optimization pass id.
    pub pass_id: &'static str,
    /// Minimum active frontier items required before this pass is profitable.
    pub min_frontier_items: u64,
    /// Minimum repeated graph executions required before this pass is profitable.
    pub min_reuse_count: u64,
    /// Minimum readback bytes avoided before this pass is profitable.
    pub min_avoided_readback_bytes: u64,
    /// Estimated planning/compile cost in nanoseconds.
    pub planning_cost_ns: u64,
    /// Scratch bytes needed by the pass while planning/executing.
    pub scratch_bytes: u64,
    /// Expected speedup in basis points from committed benchmark evidence.
    pub expected_speedup_bps: u32,
    /// Whether the pass is mandatory when its thresholds are met.
    pub mandatory_when_profitable: bool,
}

/// Runtime benchmark sample used to select CUDA optimization passes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaBenchmarkPassSelectionSample {
    /// Active frontier items in the current graph/query batch.
    pub frontier_items: u64,
    /// Number of repeated executions over the same resident graph shape.
    pub reuse_count: u64,
    /// Readback bytes the workload can avoid with compaction/aggregation.
    pub avoidable_readback_bytes: u64,
    /// Maximum total planning cost allowed.
    pub planning_budget_ns: u64,
    /// Maximum scratch bytes allowed for selected passes.
    pub scratch_budget_bytes: u64,
}

/// One skipped CUDA optimization with a stable reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CudaSkippedBenchmarkPass {
    /// Registered optimization pass id.
    pub pass_id: &'static str,
    /// Stable reason.
    pub reason: CudaBenchmarkPassSkipReason,
}

/// Stable skip reason for a CUDA optimization candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CudaBenchmarkPassSkipReason {
    /// Frontier is too small for this pass to pay for itself.
    FrontierBelowThreshold,
    /// Graph reuse is too low for residency/cache/fusion work to amortize.
    ReuseBelowThreshold,
    /// Readback pressure is too low for compaction/aggregation to pay off.
    ReadbackBelowThreshold,
    /// Planning budget would be exceeded.
    PlanningBudgetExceeded,
    /// Scratch budget would be exceeded.
    ScratchBudgetExceeded,
}

/// CUDA pass-selection output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CudaBenchmarkPassSelectionPlan {
    /// Selected pass ids in benchmark-value order.
    pub selected_pass_ids: Vec<&'static str>,
    /// Skipped pass ids with stable reasons.
    pub skipped_passes: Vec<CudaSkippedBenchmarkPass>,
    /// Total selected planning cost.
    pub total_planning_cost_ns: u64,
    /// Total selected scratch bytes.
    pub total_scratch_bytes: u64,
    /// Product of selected speedup multipliers in basis points.
    pub projected_speedup_bps: u64,
}

/// Caller-owned scratch for repeated CUDA benchmark pass selection.
#[derive(Debug, Default)]
pub struct CudaBenchmarkPassSelectionScratch {
    seen: FxHashSet<&'static str>,
    ordered_indices: Vec<usize>,
}

impl CudaBenchmarkPassSelectionScratch {
    /// Allocate empty reusable pass-selection scratch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate reusable pass-selection scratch for a known candidate count.
    pub fn try_with_capacity(
        candidate_count: usize,
    ) -> Result<Self, CudaBenchmarkPassSelectionError> {
        let mut scratch = Self::default();
        scratch.try_reserve_candidates(candidate_count)?;
        Ok(scratch)
    }

    /// Reserve reusable pass-selection scratch for a known candidate count.
    pub fn try_reserve_candidates(
        &mut self,
        candidate_count: usize,
    ) -> Result<(), CudaBenchmarkPassSelectionError> {
        reserve_set(&mut self.seen, candidate_count, "scratch.seen")?;
        reserve_vec(
            &mut self.ordered_indices,
            candidate_count,
            "scratch.ordered_indices",
        )
    }

    /// Retained duplicate-detection capacity.
    #[must_use]
    pub fn seen_capacity(&self) -> usize {
        self.seen.capacity()
    }

    /// Retained candidate-ordering capacity.
    #[must_use]
    pub fn ordered_index_capacity(&self) -> usize {
        self.ordered_indices.capacity()
    }
}

/// CUDA benchmark-driven pass-selection errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CudaBenchmarkPassSelectionError {
    /// Candidate pass id is empty.
    EmptyPassId,
    /// Duplicate candidate pass id.
    DuplicatePassId {
        /// Duplicate pass id.
        pass_id: &'static str,
    },
    /// Candidate has no benchmark speedup evidence.
    MissingSpeedupEvidence {
        /// Invalid pass id.
        pass_id: &'static str,
    },
    /// Mandatory profitable pass could not fit the explicit budgets.
    MandatoryProfitablePassOverBudget {
        /// Pass id.
        pass_id: &'static str,
        /// Reason it could not fit.
        reason: CudaBenchmarkPassSkipReason,
    },
    /// Arithmetic overflowed.
    CountOverflow {
        /// Field being computed.
        field: &'static str,
    },
    /// Scratch or result-vector storage reservation failed before pass selection.
    StorageReserveFailed {
        /// Field being reserved.
        field: &'static str,
        /// Requested total capacity.
        requested: usize,
        /// Allocator failure details.
        message: String,
    },
}

impl std::fmt::Display for CudaBenchmarkPassSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyPassId => write!(
                f,
                "CUDA benchmark pass selection received an empty pass id. Fix: register every CUDA pass before selection."
            ),
            Self::DuplicatePassId { pass_id } => write!(
                f,
                "CUDA benchmark pass selection received duplicate pass `{pass_id}`. Fix: keep one benchmark row per pass."
            ),
            Self::MissingSpeedupEvidence { pass_id } => write!(
                f,
                "CUDA benchmark pass `{pass_id}` has no positive speedup evidence. Fix: add committed benchmark evidence or remove the candidate."
            ),
            Self::MandatoryProfitablePassOverBudget { pass_id, reason } => write!(
                f,
                "CUDA mandatory profitable pass `{pass_id}` was blocked by {reason:?}. Fix: raise the explicit budget or shard before pass selection."
            ),
            Self::CountOverflow { field } => write!(
                f,
                "CUDA benchmark pass selection overflowed while computing {field}. Fix: shard the optimization candidate set."
            ),
            Self::StorageReserveFailed {
                field,
                requested,
                message,
            } => write!(
                f,
                "CUDA benchmark pass selection failed to reserve {field} for {requested} entries: {message}. Fix: shard the optimization candidate set before CUDA pass selection."
            ),
        }
    }
}

impl std::error::Error for CudaBenchmarkPassSelectionError {}

/// Select CUDA optimization passes from benchmark evidence and workload stats.
pub fn select_cuda_benchmark_passes(
    candidates: &[CudaBenchmarkPassCandidate],
    sample: CudaBenchmarkPassSelectionSample,
) -> Result<CudaBenchmarkPassSelectionPlan, CudaBenchmarkPassSelectionError> {
    let mut scratch = CudaBenchmarkPassSelectionScratch::try_with_capacity(candidates.len())?;
    select_cuda_benchmark_passes_with_scratch(candidates, sample, &mut scratch)
}

/// Select CUDA optimization passes using caller-owned temporary storage.
pub fn select_cuda_benchmark_passes_with_scratch(
    candidates: &[CudaBenchmarkPassCandidate],
    sample: CudaBenchmarkPassSelectionSample,
    scratch: &mut CudaBenchmarkPassSelectionScratch,
) -> Result<CudaBenchmarkPassSelectionPlan, CudaBenchmarkPassSelectionError> {
    scratch.seen.clear();
    scratch.ordered_indices.clear();
    scratch.try_reserve_candidates(candidates.len())?;
    for (index, candidate) in candidates.iter().enumerate() {
        if candidate.pass_id.is_empty() {
            return Err(CudaBenchmarkPassSelectionError::EmptyPassId);
        }
        if !scratch.seen.insert(candidate.pass_id) {
            return Err(CudaBenchmarkPassSelectionError::DuplicatePassId {
                pass_id: candidate.pass_id,
            });
        }
        if candidate.expected_speedup_bps <= 10_000 {
            return Err(CudaBenchmarkPassSelectionError::MissingSpeedupEvidence {
                pass_id: candidate.pass_id,
            });
        }
        scratch.ordered_indices.push(index);
    }
    scratch.ordered_indices.sort_unstable_by(|&left, &right| {
        candidates[right]
            .mandatory_when_profitable
            .cmp(&candidates[left].mandatory_when_profitable)
            .then_with(|| {
                pass_value(&candidates[right])
                    .cmp(&pass_value(&candidates[left]))
                    .then_with(|| candidates[left].pass_id.cmp(candidates[right].pass_id))
            })
    });

    let (selected_pass_capacity, skipped_pass_capacity) =
        count_final_pass_buckets(candidates, sample, &scratch.ordered_indices)?;
    let mut selected_pass_ids = reserved_vec(selected_pass_capacity, "selected_pass_ids")?;
    let mut skipped_passes = reserved_vec(skipped_pass_capacity, "skipped_passes")?;
    let mut total_planning_cost_ns = 0_u64;
    let mut total_scratch_bytes = 0_u64;
    let mut projected_speedup_bps = 10_000_u64;

    for &index in &scratch.ordered_indices {
        let candidate = candidates[index];
        if sample.frontier_items < candidate.min_frontier_items {
            skipped_passes.push(skipped(
                candidate.pass_id,
                CudaBenchmarkPassSkipReason::FrontierBelowThreshold,
            ));
            continue;
        }
        if sample.reuse_count < candidate.min_reuse_count {
            skipped_passes.push(skipped(
                candidate.pass_id,
                CudaBenchmarkPassSkipReason::ReuseBelowThreshold,
            ));
            continue;
        }
        if sample.avoidable_readback_bytes < candidate.min_avoided_readback_bytes {
            skipped_passes.push(skipped(
                candidate.pass_id,
                CudaBenchmarkPassSkipReason::ReadbackBelowThreshold,
            ));
            continue;
        }

        let next_planning = checked_add(
            total_planning_cost_ns,
            candidate.planning_cost_ns,
            "planning cost",
        )?;
        if next_planning > sample.planning_budget_ns {
            handle_budget_skip(
                candidate,
                CudaBenchmarkPassSkipReason::PlanningBudgetExceeded,
                &mut skipped_passes,
            )?;
            continue;
        }
        let next_scratch = checked_add(
            total_scratch_bytes,
            candidate.scratch_bytes,
            "scratch bytes",
        )?;
        if next_scratch > sample.scratch_budget_bytes {
            handle_budget_skip(
                candidate,
                CudaBenchmarkPassSkipReason::ScratchBudgetExceeded,
                &mut skipped_passes,
            )?;
            continue;
        }

        selected_pass_ids.push(candidate.pass_id);
        total_planning_cost_ns = next_planning;
        total_scratch_bytes = next_scratch;
        projected_speedup_bps = checked_mul(
            projected_speedup_bps,
            u64::from(candidate.expected_speedup_bps),
            "projected speedup product",
        )? / 10_000;
    }

    Ok(CudaBenchmarkPassSelectionPlan {
        selected_pass_ids,
        skipped_passes,
        total_planning_cost_ns,
        total_scratch_bytes,
        projected_speedup_bps,
    })
}

fn pass_value(candidate: &CudaBenchmarkPassCandidate) -> u128 {
    u128::from(candidate.expected_speedup_bps)
        * (u128::from(candidate.min_frontier_items)
            + u128::from(candidate.min_reuse_count)
            + u128::from(candidate.min_avoided_readback_bytes))
}

fn count_final_pass_buckets(
    candidates: &[CudaBenchmarkPassCandidate],
    sample: CudaBenchmarkPassSelectionSample,
    ordered_indices: &[usize],
) -> Result<(usize, usize), CudaBenchmarkPassSelectionError> {
    let mut selected = 0usize;
    let mut skipped = 0usize;
    let mut total_planning_cost_ns = 0_u64;
    let mut total_scratch_bytes = 0_u64;
    for &index in ordered_indices {
        let candidate = candidates[index];
        if sample.frontier_items < candidate.min_frontier_items
            || sample.reuse_count < candidate.min_reuse_count
            || sample.avoidable_readback_bytes < candidate.min_avoided_readback_bytes
        {
            skipped = checked_add_usize(skipped, 1, "skipped pass count")?;
            continue;
        }
        let next_planning = checked_add(
            total_planning_cost_ns,
            candidate.planning_cost_ns,
            "planning cost",
        )?;
        if next_planning > sample.planning_budget_ns {
            if candidate.mandatory_when_profitable {
                return Err(
                    CudaBenchmarkPassSelectionError::MandatoryProfitablePassOverBudget {
                        pass_id: candidate.pass_id,
                        reason: CudaBenchmarkPassSkipReason::PlanningBudgetExceeded,
                    },
                );
            }
            skipped = checked_add_usize(skipped, 1, "skipped pass count")?;
            continue;
        }
        let next_scratch = checked_add(
            total_scratch_bytes,
            candidate.scratch_bytes,
            "scratch bytes",
        )?;
        if next_scratch > sample.scratch_budget_bytes {
            if candidate.mandatory_when_profitable {
                return Err(
                    CudaBenchmarkPassSelectionError::MandatoryProfitablePassOverBudget {
                        pass_id: candidate.pass_id,
                        reason: CudaBenchmarkPassSkipReason::ScratchBudgetExceeded,
                    },
                );
            }
            skipped = checked_add_usize(skipped, 1, "skipped pass count")?;
            continue;
        }
        selected = checked_add_usize(selected, 1, "selected pass count")?;
        total_planning_cost_ns = next_planning;
        total_scratch_bytes = next_scratch;
    }
    Ok((selected, skipped))
}

fn skipped(pass_id: &'static str, reason: CudaBenchmarkPassSkipReason) -> CudaSkippedBenchmarkPass {
    CudaSkippedBenchmarkPass { pass_id, reason }
}

fn handle_budget_skip(
    candidate: CudaBenchmarkPassCandidate,
    reason: CudaBenchmarkPassSkipReason,
    skipped_passes: &mut Vec<CudaSkippedBenchmarkPass>,
) -> Result<(), CudaBenchmarkPassSelectionError> {
    if candidate.mandatory_when_profitable {
        return Err(
            CudaBenchmarkPassSelectionError::MandatoryProfitablePassOverBudget {
                pass_id: candidate.pass_id,
                reason,
            },
        );
    }
    skipped_passes.push(skipped(candidate.pass_id, reason));
    Ok(())
}

fn checked_add(
    lhs: u64,
    rhs: u64,
    field: &'static str,
) -> Result<u64, CudaBenchmarkPassSelectionError> {
    lhs.checked_add(rhs)
        .ok_or(CudaBenchmarkPassSelectionError::CountOverflow { field })
}

fn checked_mul(
    lhs: u64,
    rhs: u64,
    field: &'static str,
) -> Result<u64, CudaBenchmarkPassSelectionError> {
    lhs.checked_mul(rhs)
        .ok_or(CudaBenchmarkPassSelectionError::CountOverflow { field })
}

fn checked_add_usize(
    lhs: usize,
    rhs: usize,
    field: &'static str,
) -> Result<usize, CudaBenchmarkPassSelectionError> {
    lhs.checked_add(rhs)
        .ok_or(CudaBenchmarkPassSelectionError::CountOverflow { field })
}

fn reserve_vec<T>(
    vec: &mut Vec<T>,
    capacity: usize,
    field: &'static str,
) -> Result<(), CudaBenchmarkPassSelectionError> {
    if vec.capacity() >= capacity {
        return Ok(());
    }
    let additional = capacity - vec.capacity();
    vec.try_reserve_exact(additional).map_err(|error| {
        CudaBenchmarkPassSelectionError::StorageReserveFailed {
            field,
            requested: capacity,
            message: error.to_string(),
        }
    })
}

fn reserved_vec<T>(
    capacity: usize,
    field: &'static str,
) -> Result<Vec<T>, CudaBenchmarkPassSelectionError> {
    let mut vec = Vec::new();
    reserve_vec(&mut vec, capacity, field)?;
    Ok(vec)
}

fn reserve_set<T>(
    set: &mut FxHashSet<T>,
    capacity: usize,
    field: &'static str,
) -> Result<(), CudaBenchmarkPassSelectionError>
where
    T: Eq + Hash,
{
    if set.capacity() >= capacity {
        return Ok(());
    }
    let additional = capacity - set.capacity();
    set.try_reserve(additional).map_err(|error| {
        CudaBenchmarkPassSelectionError::StorageReserveFailed {
            field,
            requested: capacity,
            message: error.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_pass_selection_picks_profitable_cuda_passes_by_value() {
        let plan = select_cuda_benchmark_passes(
            &[
                candidate(
                    "cuda.adjacent-launch-fusion",
                    1_000,
                    4,
                    0,
                    100,
                    64,
                    18_000,
                    true,
                ),
                candidate("cuda.result-compaction", 1, 1, 4_096, 20, 16, 12_000, false),
                candidate("cuda.megakernel-plan-cache", 1, 64, 0, 50, 32, 25_000, true),
            ],
            CudaBenchmarkPassSelectionSample {
                frontier_items: 2_000,
                reuse_count: 128,
                avoidable_readback_bytes: 8_192,
                planning_budget_ns: 200,
                scratch_budget_bytes: 128,
            },
        )
        .expect("profitable passes should select");

        assert_eq!(plan.selected_pass_ids.len(), 3);
        assert!(plan
            .selected_pass_ids
            .contains(&"cuda.megakernel-plan-cache"));
        assert!(plan
            .selected_pass_ids
            .contains(&"cuda.adjacent-launch-fusion"));
        assert!(plan.selected_pass_ids.contains(&"cuda.result-compaction"));
        assert_eq!(plan.total_planning_cost_ns, 170);
        assert_eq!(plan.total_scratch_bytes, 112);
        assert!(plan.projected_speedup_bps > 50_000);
    }

    #[test]
    fn benchmark_pass_selection_skips_unprofitable_passes_with_stable_reasons() {
        let plan = select_cuda_benchmark_passes(
            &[
                candidate(
                    "cuda.adjacent-launch-fusion",
                    1_000,
                    4,
                    0,
                    10,
                    8,
                    15_000,
                    false,
                ),
                candidate("cuda.result-compaction", 1, 1, 4_096, 10, 8, 11_000, false),
            ],
            CudaBenchmarkPassSelectionSample {
                frontier_items: 10,
                reuse_count: 1,
                avoidable_readback_bytes: 128,
                planning_budget_ns: 100,
                scratch_budget_bytes: 100,
            },
        )
        .expect("unprofitable optional passes should skip");

        assert_eq!(plan.selected_pass_ids, Vec::<&'static str>::new());
        assert_eq!(plan.skipped_passes.len(), 2);
        assert!(plan.skipped_passes.contains(&CudaSkippedBenchmarkPass {
            pass_id: "cuda.adjacent-launch-fusion",
            reason: CudaBenchmarkPassSkipReason::FrontierBelowThreshold,
        }));
        assert!(plan.skipped_passes.contains(&CudaSkippedBenchmarkPass {
            pass_id: "cuda.result-compaction",
            reason: CudaBenchmarkPassSkipReason::ReadbackBelowThreshold,
        }));
    }

    #[test]
    fn benchmark_pass_selection_ranks_huge_values_without_saturation_ties() {
        let plan = select_cuda_benchmark_passes(
            &[
                candidate(
                    "cuda.a-lexicographic-low-value",
                    u64::MAX,
                    u64::MAX,
                    u64::MAX - 1,
                    1,
                    1,
                    11_000,
                    false,
                ),
                candidate(
                    "cuda.z-lexicographic-high-value",
                    u64::MAX,
                    u64::MAX,
                    u64::MAX,
                    1,
                    1,
                    11_000,
                    false,
                ),
            ],
            CudaBenchmarkPassSelectionSample {
                frontier_items: u64::MAX,
                reuse_count: u64::MAX,
                avoidable_readback_bytes: u64::MAX,
                planning_budget_ns: 10,
                scratch_budget_bytes: 10,
            },
        )
        .expect("huge benchmark evidence should rank without saturating value ties");

        assert_eq!(
            plan.selected_pass_ids[0],
            "cuda.z-lexicographic-high-value",
            "Fix: CUDA pass ranking must use widened arithmetic; saturating u64 scoring would tie these candidates and incorrectly choose lexicographic order."
        );
    }

    #[test]
    fn benchmark_pass_selection_rejects_missing_evidence_and_blocked_mandatory() {
        assert_eq!(
            select_cuda_benchmark_passes(
                &[candidate("cuda.bad", 1, 1, 0, 1, 1, 10_000, false)],
                sample(),
            )
            .expect_err("zero speedup evidence should fail"),
            CudaBenchmarkPassSelectionError::MissingSpeedupEvidence {
                pass_id: "cuda.bad",
            }
        );
        assert_eq!(
            select_cuda_benchmark_passes(
                &[candidate("cuda.mandatory", 1, 1, 0, 101, 1, 11_000, true)],
                sample(),
            )
            .expect_err("mandatory profitable pass cannot exceed budget"),
            CudaBenchmarkPassSelectionError::MandatoryProfitablePassOverBudget {
                pass_id: "cuda.mandatory",
                reason: CudaBenchmarkPassSkipReason::PlanningBudgetExceeded,
            }
        );
    }

    #[test]
    fn benchmark_pass_selection_does_not_let_optional_passes_starve_mandatory_cuda_passes() {
        let plan = select_cuda_benchmark_passes(
            &[
                candidate(
                    "cuda.optional-high-value",
                    1,
                    1,
                    1_000_000,
                    100,
                    1,
                    20_000,
                    false,
                ),
                candidate("cuda.mandatory-low-value", 1, 1, 1, 100, 1, 11_000, true),
            ],
            CudaBenchmarkPassSelectionSample {
                frontier_items: 1,
                reuse_count: 1,
                avoidable_readback_bytes: 1_000_000,
                planning_budget_ns: 100,
                scratch_budget_bytes: 8,
            },
        )
        .expect("mandatory profitable CUDA pass must reserve budget before optional passes");

        assert_eq!(plan.selected_pass_ids, vec!["cuda.mandatory-low-value"]);
        assert_eq!(
            plan.skipped_passes,
            vec![CudaSkippedBenchmarkPass {
                pass_id: "cuda.optional-high-value",
                reason: CudaBenchmarkPassSkipReason::PlanningBudgetExceeded,
            }]
        );
    }

    #[test]
    fn benchmark_pass_selection_avoids_tree_sets_and_candidate_vector_copies() {
        let src = include_str!("benchmark_pass_selection.rs");
        assert!(
            !src.contains(concat!("BTree", "Set")),
            "Fix: CUDA benchmark pass selection should hash pass ids and sort candidate indices by value."
        );
        assert!(
            !src.contains(concat!("candidates", ".to_vec()")),
            "Fix: CUDA benchmark pass selection should not copy all candidates before value ordering."
        );
        assert!(
            src.contains("CudaBenchmarkPassSelectionScratch::try_with_capacity(candidates.len())?"),
            "Fix: CUDA benchmark pass selection must stage scratch with fallible release-path allocation."
        );
        assert!(
            src.contains("scratch.try_reserve_candidates(candidates.len())?"),
            "Fix: caller-owned CUDA benchmark pass-selection scratch must grow through fallible reservation."
        );
        assert!(
            src.contains("fn reserve_vec<T>("),
            "Fix: CUDA benchmark pass-selection result vectors must use typed fallible reservation."
        );
        assert!(
            src.contains("fn reserve_set<T>("),
            "Fix: CUDA benchmark pass-selection duplicate detection must use typed fallible reservation."
        );
        assert!(
            src.contains("StorageReserveFailed"),
            "Fix: CUDA benchmark pass-selection allocation failures must surface as actionable planning errors."
        );
        assert!(
            !src.contains(concat!("FxHashSet::with_capacity", "_and_hasher")),
            "Fix: CUDA benchmark pass-selection scratch hash storage must not allocate infallibly."
        );
        assert!(
            !src.contains(concat!("Vec::with_capacity", "(candidate_count)")),
            "Fix: CUDA benchmark pass-selection scratch vectors must not allocate infallibly."
        );
        assert!(
            !src.contains(concat!("Vec::with_capacity", "(candidates.len())")),
            "Fix: CUDA benchmark pass-selection result vectors must not allocate infallibly."
        );
        assert!(
            !src.contains(concat!("scratch.seen", ".reserve(candidates.len())")),
            "Fix: CUDA benchmark pass-selection duplicate scratch must not grow infallibly."
        );
        assert!(
            !src.contains(concat!(
                "scratch.ordered_indices",
                ".reserve(candidates.len())"
            )),
            "Fix: CUDA benchmark pass-selection ordering scratch must not grow infallibly."
        );
    }

    #[test]
    fn benchmark_pass_selection_reuses_caller_owned_candidate_scratch() {
        let mut scratch =
            CudaBenchmarkPassSelectionScratch::try_with_capacity(64).expect("scratch capacity");
        let names = [
            "cuda.synthetic.00",
            "cuda.synthetic.01",
            "cuda.synthetic.02",
            "cuda.synthetic.03",
            "cuda.synthetic.04",
            "cuda.synthetic.05",
            "cuda.synthetic.06",
            "cuda.synthetic.07",
            "cuda.synthetic.08",
            "cuda.synthetic.09",
            "cuda.synthetic.10",
            "cuda.synthetic.11",
            "cuda.synthetic.12",
            "cuda.synthetic.13",
            "cuda.synthetic.14",
            "cuda.synthetic.15",
        ];
        let mut wide = Vec::new();
        wide.try_reserve_exact(names.len())
            .expect("synthetic pass vector capacity");
        for (index, name) in names.iter().copied().enumerate() {
            wide.push(candidate(
                name,
                1,
                1,
                1,
                1,
                1,
                11_000 + u32::try_from(index).expect("synthetic pass index fits in u32"),
                false,
            ));
        }
        let first = select_cuda_benchmark_passes_with_scratch(
            &wide,
            CudaBenchmarkPassSelectionSample {
                frontier_items: 64,
                reuse_count: 64,
                avoidable_readback_bytes: 64,
                planning_budget_ns: 128,
                scratch_budget_bytes: 128,
            },
            &mut scratch,
        )
        .expect("wide benchmark pass selection should plan with reusable scratch");
        let seen_capacity = scratch.seen_capacity();
        let ordered_index_capacity = scratch.ordered_index_capacity();

        assert_eq!(first.selected_pass_ids.len(), names.len());

        let second = select_cuda_benchmark_passes_with_scratch(
            &[
                candidate("cuda.reused.high", 1, 1, 1, 10, 8, 20_000, false),
                candidate("cuda.reused.low", 1, 1, 1, 10, 8, 12_000, false),
            ],
            sample(),
            &mut scratch,
        )
        .expect("smaller benchmark pass selection should reuse previous scratch");

        assert_eq!(second.selected_pass_ids[0], "cuda.reused.high");
        assert!(scratch.seen_capacity() >= seen_capacity);
        assert!(scratch.ordered_index_capacity() >= ordered_index_capacity);

        let src = include_str!("benchmark_pass_selection.rs");
        assert!(
            src.contains("pub fn select_cuda_benchmark_passes_with_scratch"),
            "Fix: release callers need a scratch-aware CUDA benchmark pass-selection path"
        );
        assert!(
            src.contains("scratch.ordered_indices.sort_unstable_by"),
            "Fix: CUDA benchmark pass selection should sort retained candidate indices in place"
        );
    }

    fn sample() -> CudaBenchmarkPassSelectionSample {
        CudaBenchmarkPassSelectionSample {
            frontier_items: 10,
            reuse_count: 10,
            avoidable_readback_bytes: 10,
            planning_budget_ns: 100,
            scratch_budget_bytes: 100,
        }
    }

    fn candidate(
        pass_id: &'static str,
        min_frontier_items: u64,
        min_reuse_count: u64,
        min_avoided_readback_bytes: u64,
        planning_cost_ns: u64,
        scratch_bytes: u64,
        expected_speedup_bps: u32,
        mandatory_when_profitable: bool,
    ) -> CudaBenchmarkPassCandidate {
        CudaBenchmarkPassCandidate {
            pass_id,
            min_frontier_items,
            min_reuse_count,
            min_avoided_readback_bytes,
            planning_cost_ns,
            scratch_bytes,
            expected_speedup_bps,
            mandatory_when_profitable,
        }
    }
}
