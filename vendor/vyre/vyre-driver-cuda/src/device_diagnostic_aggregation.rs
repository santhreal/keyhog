//! CUDA device-side diagnostic aggregation planning.
//!
//! Frontend diagnostics are sparse relative to token/fact streams. Reading the
//! whole candidate stream back to the host and filtering on CPU is release-path
//! wrong: it moves bytes that the GPU already proved irrelevant. This module
//! plans the resident counter and compact-record slabs needed for CUDA kernels
//! to aggregate diagnostics on device, then read back only counters and compact
//! diagnostic records.

use rustc_hash::FxHashSet;
use std::hash::Hash;

/// One CUDA-resident diagnostic shard before aggregation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaDiagnosticShard {
    /// Stable shard id.
    pub shard: u32,
    /// Candidate token/fact items inspected by the device.
    pub candidate_items: u64,
    /// Diagnostics emitted by the device for this shard.
    pub emitted_diagnostics: u64,
    /// Bytes per candidate item in the unaggregated stream.
    pub raw_item_bytes: u64,
    /// Bytes per compact diagnostic record.
    pub diagnostic_record_bytes: u64,
    /// Bytes for device-side counters and overflow flags for this shard.
    pub counter_bytes: u64,
    /// Non-zero severity/category mask represented by emitted diagnostics.
    pub severity_mask: u32,
}

/// One compact diagnostic readback range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaDiagnosticCompactRange {
    /// Source shard id.
    pub shard: u32,
    /// Offset in the compact diagnostic slab.
    pub compact_offset: u64,
    /// Diagnostics represented in this range.
    pub records: u64,
    /// Bytes copied into the compact diagnostic slab.
    pub bytes: u64,
}

/// CUDA diagnostic aggregation plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CudaDiagnosticAggregationPlan {
    /// Compact readback ranges ordered by shard id.
    pub compact_ranges: Vec<CudaDiagnosticCompactRange>,
    /// Total counter/overflow bytes read by the host.
    pub counter_readback_bytes: u64,
    /// Total compact diagnostic record bytes read by the host.
    pub compact_readback_bytes: u64,
    /// Total host readback bytes after device aggregation.
    pub host_readback_bytes: u64,
    /// Bytes that would have been read by a raw candidate-stream readback.
    pub raw_candidate_readback_bytes: u64,
    /// Bytes avoided by aggregating on device.
    pub avoided_readback_bytes: u64,
    /// Aggregate compression ratio in basis points.
    pub compression_ratio_bps: u32,
    /// Diagnostics omitted because per-shard caps were reached.
    pub overflow_records: u64,
    /// Whether any shard needs a device-side overflow flag.
    pub requires_overflow_flag: bool,
    /// Whether aggregation requires a device-side prefix scan over records.
    pub requires_device_prefix_scan: bool,
    /// This plan never requires host participation before final readback.
    pub final_only_host_readback: bool,
}

/// Caller-owned scratch for repeated CUDA diagnostic aggregation planning.
#[derive(Debug, Default)]
pub struct CudaDiagnosticAggregationScratch {
    ids: FxHashSet<u32>,
    ordered_indices: Vec<usize>,
}

impl CudaDiagnosticAggregationScratch {
    /// Allocate empty reusable diagnostic aggregation scratch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate reusable diagnostic aggregation scratch for a known shard count.
    pub fn try_with_capacity(shard_count: usize) -> Result<Self, CudaDiagnosticAggregationError> {
        let mut scratch = Self::default();
        scratch.try_reserve_shards(shard_count)?;
        Ok(scratch)
    }

    /// Reserve reusable diagnostic aggregation scratch for a known shard count.
    pub fn try_reserve_shards(
        &mut self,
        shard_count: usize,
    ) -> Result<(), CudaDiagnosticAggregationError> {
        reserve_set(&mut self.ids, shard_count, "scratch.ids")?;
        reserve_vec(
            &mut self.ordered_indices,
            shard_count,
            "scratch.ordered_indices",
        )
    }

    /// Retained duplicate-detection capacity.
    #[must_use]
    pub fn id_capacity(&self) -> usize {
        self.ids.capacity()
    }

    /// Retained shard-ordering capacity.
    #[must_use]
    pub fn ordered_index_capacity(&self) -> usize {
        self.ordered_indices.capacity()
    }
}

/// CUDA diagnostic aggregation planning errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CudaDiagnosticAggregationError {
    /// Duplicate shard id.
    DuplicateShard {
        /// Duplicate shard id.
        shard: u32,
    },
    /// Candidate items cannot be zero for an emitted shard.
    ZeroCandidates {
        /// Invalid shard id.
        shard: u32,
    },
    /// Raw candidate ABI width must be non-zero.
    ZeroRawItemBytes {
        /// Invalid shard id.
        shard: u32,
    },
    /// Compact diagnostic ABI width must be non-zero when diagnostics exist.
    ZeroDiagnosticRecordBytes {
        /// Invalid shard id.
        shard: u32,
    },
    /// Diagnostic count cannot exceed inspected candidate items.
    EmittedExceedsCandidates {
        /// Invalid shard id.
        shard: u32,
        /// Emitted diagnostics.
        emitted_diagnostics: u64,
        /// Candidate items.
        candidate_items: u64,
    },
    /// Non-empty diagnostic shards need a non-zero severity/category mask.
    MissingSeverityMask {
        /// Invalid shard id.
        shard: u32,
    },
    /// Per-shard compact cap cannot be zero.
    ZeroRecordCap,
    /// Byte arithmetic overflowed.
    ByteCountOverflow {
        /// Field being computed.
        field: &'static str,
    },
    /// Aggregation slabs exceed the explicit device budget.
    OverBudget {
        /// Required resident/readback bytes.
        required_bytes: u64,
        /// Caller-provided budget.
        budget_bytes: u64,
    },
    /// Scratch or result-vector storage reservation failed before launch planning.
    StorageReserveFailed {
        /// Field being reserved.
        field: &'static str,
        /// Requested total capacity.
        requested: usize,
        /// Allocator failure details.
        message: String,
    },
}

impl std::fmt::Display for CudaDiagnosticAggregationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateShard { shard } => write!(
                f,
                "CUDA diagnostic aggregation received duplicate shard {shard}. Fix: assign unique diagnostic shard ids before CUDA compaction."
            ),
            Self::ZeroCandidates { shard } => write!(
                f,
                "CUDA diagnostic shard {shard} emitted diagnostics with zero candidates. Fix: emit diagnostic shards only after device candidate classification."
            ),
            Self::ZeroRawItemBytes { shard } => write!(
                f,
                "CUDA diagnostic shard {shard} has raw_item_bytes=0. Fix: pass the concrete token/fact candidate ABI width."
            ),
            Self::ZeroDiagnosticRecordBytes { shard } => write!(
                f,
                "CUDA diagnostic shard {shard} has diagnostic_record_bytes=0. Fix: pass the compact diagnostic record ABI width."
            ),
            Self::EmittedExceedsCandidates {
                shard,
                emitted_diagnostics,
                candidate_items,
            } => write!(
                f,
                "CUDA diagnostic shard {shard} emitted {emitted_diagnostics} diagnostics from {candidate_items} candidates. Fix: clamp emission to the device candidate count or split the shard."
            ),
            Self::MissingSeverityMask { shard } => write!(
                f,
                "CUDA diagnostic shard {shard} emitted diagnostics without a severity/category mask. Fix: preserve diagnostic class bits during device aggregation."
            ),
            Self::ZeroRecordCap => write!(
                f,
                "CUDA diagnostic aggregation received a zero per-shard record cap. Fix: set an explicit compact diagnostic cap before launch."
            ),
            Self::ByteCountOverflow { field } => write!(
                f,
                "CUDA diagnostic aggregation overflowed while computing {field}. Fix: shard diagnostic aggregation before readback planning."
            ),
            Self::OverBudget {
                required_bytes,
                budget_bytes,
            } => write!(
                f,
                "CUDA diagnostic aggregation requires {required_bytes} bytes but budget allows {budget_bytes}. Fix: reduce per-shard caps, split shards, or raise the explicit CUDA budget."
            ),
            Self::StorageReserveFailed {
                field,
                requested,
                message,
            } => write!(
                f,
                "CUDA diagnostic aggregation failed to reserve {field} for {requested} entries: {message}. Fix: shard diagnostic aggregation before CUDA launch planning."
            ),
        }
    }
}

impl std::error::Error for CudaDiagnosticAggregationError {}

/// Plan CUDA-side diagnostic aggregation and final-only compact readback.
pub fn plan_cuda_device_diagnostic_aggregation(
    shards: &[CudaDiagnosticShard],
    max_records_per_shard: u64,
    budget_bytes: u64,
) -> Result<CudaDiagnosticAggregationPlan, CudaDiagnosticAggregationError> {
    let mut scratch = CudaDiagnosticAggregationScratch::try_with_capacity(shards.len())?;
    plan_cuda_device_diagnostic_aggregation_with_scratch(
        shards,
        max_records_per_shard,
        budget_bytes,
        &mut scratch,
    )
}

/// Plan CUDA-side diagnostic aggregation using caller-owned temporary storage.
pub fn plan_cuda_device_diagnostic_aggregation_with_scratch(
    shards: &[CudaDiagnosticShard],
    max_records_per_shard: u64,
    budget_bytes: u64,
    scratch: &mut CudaDiagnosticAggregationScratch,
) -> Result<CudaDiagnosticAggregationPlan, CudaDiagnosticAggregationError> {
    if max_records_per_shard == 0 {
        return Err(CudaDiagnosticAggregationError::ZeroRecordCap);
    }

    scratch.ids.clear();
    scratch.ordered_indices.clear();
    scratch.try_reserve_shards(shards.len())?;
    let mut counter_readback_bytes = 0_u64;
    let mut compact_readback_bytes = 0_u64;
    let mut raw_candidate_readback_bytes = 0_u64;
    let mut overflow_records = 0_u64;
    let mut non_empty_diagnostic_shards = 0usize;

    for (index, shard) in shards.iter().copied().enumerate() {
        validate_shard(shard, &mut scratch.ids)?;

        let raw_bytes = checked_mul(
            shard.candidate_items,
            shard.raw_item_bytes,
            "raw candidate readback bytes",
        )?;
        raw_candidate_readback_bytes = checked_add(
            raw_candidate_readback_bytes,
            raw_bytes,
            "total raw candidate readback bytes",
        )?;
        counter_readback_bytes = checked_add(
            counter_readback_bytes,
            shard.counter_bytes,
            "counter readback bytes",
        )?;
        if shard.emitted_diagnostics != 0 {
            non_empty_diagnostic_shards = checked_add_usize(
                non_empty_diagnostic_shards,
                1,
                "non-empty diagnostic shard count",
            )?;
        }
        scratch.ordered_indices.push(index);
    }
    scratch
        .ordered_indices
        .sort_unstable_by_key(|&index| shards[index].shard);

    let mut compact_ranges = reserved_vec(non_empty_diagnostic_shards, "compact_ranges")?;

    for &index in &scratch.ordered_indices {
        let shard = shards[index];
        if shard.emitted_diagnostics == 0 {
            continue;
        }

        let compact_records = shard.emitted_diagnostics.min(max_records_per_shard);
        let omitted = shard.emitted_diagnostics - compact_records;
        overflow_records = checked_add(overflow_records, omitted, "overflow records")?;
        let compact_bytes = checked_mul(
            compact_records,
            shard.diagnostic_record_bytes,
            "compact diagnostic bytes",
        )?;
        compact_ranges.push(CudaDiagnosticCompactRange {
            shard: shard.shard,
            compact_offset: compact_readback_bytes,
            records: compact_records,
            bytes: compact_bytes,
        });
        compact_readback_bytes = checked_add(
            compact_readback_bytes,
            compact_bytes,
            "total compact diagnostic bytes",
        )?;
    }

    let host_readback_bytes = checked_add(
        counter_readback_bytes,
        compact_readback_bytes,
        "host diagnostic readback bytes",
    )?;
    if host_readback_bytes > budget_bytes {
        return Err(CudaDiagnosticAggregationError::OverBudget {
            required_bytes: host_readback_bytes,
            budget_bytes,
        });
    }
    let compression_ratio_bps =
        compression_ratio_bps(host_readback_bytes, raw_candidate_readback_bytes);

    Ok(CudaDiagnosticAggregationPlan {
        compact_ranges,
        counter_readback_bytes,
        compact_readback_bytes,
        host_readback_bytes,
        raw_candidate_readback_bytes,
        avoided_readback_bytes: checked_sub(
            raw_candidate_readback_bytes,
            host_readback_bytes,
            "avoided readback bytes",
        )?,
        compression_ratio_bps,
        overflow_records,
        requires_overflow_flag: overflow_records != 0,
        requires_device_prefix_scan: non_empty_diagnostic_shards > 1,
        final_only_host_readback: true,
    })
}

fn validate_shard(
    shard: CudaDiagnosticShard,
    ids: &mut FxHashSet<u32>,
) -> Result<(), CudaDiagnosticAggregationError> {
    if !ids.insert(shard.shard) {
        return Err(CudaDiagnosticAggregationError::DuplicateShard { shard: shard.shard });
    }
    if shard.raw_item_bytes == 0 {
        return Err(CudaDiagnosticAggregationError::ZeroRawItemBytes { shard: shard.shard });
    }
    if shard.emitted_diagnostics > shard.candidate_items {
        return Err(CudaDiagnosticAggregationError::EmittedExceedsCandidates {
            shard: shard.shard,
            emitted_diagnostics: shard.emitted_diagnostics,
            candidate_items: shard.candidate_items,
        });
    }
    if shard.emitted_diagnostics != 0 && shard.candidate_items == 0 {
        return Err(CudaDiagnosticAggregationError::ZeroCandidates { shard: shard.shard });
    }
    if shard.emitted_diagnostics != 0 && shard.diagnostic_record_bytes == 0 {
        return Err(CudaDiagnosticAggregationError::ZeroDiagnosticRecordBytes {
            shard: shard.shard,
        });
    }
    if shard.emitted_diagnostics != 0 && shard.severity_mask == 0 {
        return Err(CudaDiagnosticAggregationError::MissingSeverityMask { shard: shard.shard });
    }
    Ok(())
}

fn checked_mul(
    lhs: u64,
    rhs: u64,
    field: &'static str,
) -> Result<u64, CudaDiagnosticAggregationError> {
    lhs.checked_mul(rhs)
        .ok_or(CudaDiagnosticAggregationError::ByteCountOverflow { field })
}

fn checked_add(
    lhs: u64,
    rhs: u64,
    field: &'static str,
) -> Result<u64, CudaDiagnosticAggregationError> {
    lhs.checked_add(rhs)
        .ok_or(CudaDiagnosticAggregationError::ByteCountOverflow { field })
}

fn checked_sub(
    lhs: u64,
    rhs: u64,
    field: &'static str,
) -> Result<u64, CudaDiagnosticAggregationError> {
    lhs.checked_sub(rhs)
        .ok_or(CudaDiagnosticAggregationError::ByteCountOverflow { field })
}

fn checked_add_usize(
    lhs: usize,
    rhs: usize,
    field: &'static str,
) -> Result<usize, CudaDiagnosticAggregationError> {
    lhs.checked_add(rhs)
        .ok_or(CudaDiagnosticAggregationError::ByteCountOverflow { field })
}

fn reserve_vec<T>(
    vec: &mut Vec<T>,
    capacity: usize,
    field: &'static str,
) -> Result<(), CudaDiagnosticAggregationError> {
    if vec.capacity() >= capacity {
        return Ok(());
    }
    let additional = capacity - vec.capacity();
    vec.try_reserve_exact(additional).map_err(|error| {
        CudaDiagnosticAggregationError::StorageReserveFailed {
            field,
            requested: capacity,
            message: error.to_string(),
        }
    })
}

fn reserved_vec<T>(
    capacity: usize,
    field: &'static str,
) -> Result<Vec<T>, CudaDiagnosticAggregationError> {
    let mut vec = Vec::new();
    reserve_vec(&mut vec, capacity, field)?;
    Ok(vec)
}

fn reserve_set<T>(
    set: &mut FxHashSet<T>,
    capacity: usize,
    field: &'static str,
) -> Result<(), CudaDiagnosticAggregationError>
where
    T: Eq + Hash,
{
    if set.capacity() >= capacity {
        return Ok(());
    }
    let additional = capacity - set.capacity();
    set.try_reserve(additional).map_err(|error| {
        CudaDiagnosticAggregationError::StorageReserveFailed {
            field,
            requested: capacity,
            message: error.to_string(),
        }
    })
}

fn compression_ratio_bps(host_readback_bytes: u64, raw_candidate_readback_bytes: u64) -> u32 {
    if raw_candidate_readback_bytes == 0 {
        return 0;
    }

    let ratio =
        (u128::from(host_readback_bytes) * 10_000) / u128::from(raw_candidate_readback_bytes);
    if ratio > u128::from(u32::MAX) {
        tracing::error!(
            "CUDA diagnostic compression ratio exceeded u32 basis-points. Fix: shard diagnostics or widen plan telemetry."
        );
        return u32::MAX;
    }
    ratio as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_aggregation_compacts_sparse_device_diagnostics() {
        let plan = plan_cuda_device_diagnostic_aggregation(
            &[
                shard(2, 2_000, 4, 32, 24, 16, 0b010),
                shard(1, 1_000, 2, 32, 24, 16, 0b001),
                shard(3, 4_000, 0, 32, 24, 16, 0),
            ],
            64,
            1_024,
        )
        .expect("sparse diagnostics should aggregate on device");

        assert_eq!(
            plan.compact_ranges,
            vec![
                CudaDiagnosticCompactRange {
                    shard: 1,
                    compact_offset: 0,
                    records: 2,
                    bytes: 48,
                },
                CudaDiagnosticCompactRange {
                    shard: 2,
                    compact_offset: 48,
                    records: 4,
                    bytes: 96,
                },
            ]
        );
        assert_eq!(plan.counter_readback_bytes, 48);
        assert_eq!(plan.compact_readback_bytes, 144);
        assert_eq!(plan.host_readback_bytes, 192);
        assert_eq!(plan.raw_candidate_readback_bytes, 224_000);
        assert_eq!(plan.avoided_readback_bytes, 223_808);
        assert!(plan.compression_ratio_bps < 10);
        assert!(plan.requires_device_prefix_scan);
        assert!(plan.final_only_host_readback);
    }

    #[test]
    fn diagnostic_aggregation_caps_overflow_without_host_filtering() {
        let plan = plan_cuda_device_diagnostic_aggregation(
            &[shard(7, 1_000, 10, 32, 16, 8, 0b111)],
            3,
            128,
        )
        .expect("overflow should be represented by device-side flags");

        assert_eq!(plan.compact_ranges[0].records, 3);
        assert_eq!(plan.overflow_records, 7);
        assert!(plan.requires_overflow_flag);
        assert_eq!(plan.host_readback_bytes, 56);
        assert!(
            !plan.requires_device_prefix_scan,
            "Fix: a single non-empty diagnostic shard has compact offset zero and must not schedule a device prefix scan."
        );
    }

    #[test]
    fn diagnostic_aggregation_ratio_does_not_saturate_before_division() {
        let plan = plan_cuda_device_diagnostic_aggregation(
            &[shard(9, u64::MAX / 32, 1, 32, 16, u64::MAX / 20, 0b001)],
            1,
            u64::MAX,
        )
        .expect("large diagnostic plans must retain exact ratio arithmetic");

        let expected = (((plan.host_readback_bytes as u128) * 10_000)
            / plan.raw_candidate_readback_bytes as u128) as u32;
        assert_eq!(plan.compression_ratio_bps, expected);
        assert!(plan.compression_ratio_bps > 100);
    }

    #[test]
    fn diagnostic_aggregation_rejects_invalid_or_cpu_shaped_inputs() {
        assert_eq!(
            plan_cuda_device_diagnostic_aggregation(
                &[shard(1, 8, 1, 32, 24, 8, 1), shard(1, 8, 1, 32, 24, 8, 1)],
                4,
                1_024,
            )
            .expect_err("duplicate shard should fail"),
            CudaDiagnosticAggregationError::DuplicateShard { shard: 1 }
        );
        assert_eq!(
            plan_cuda_device_diagnostic_aggregation(&[shard(2, 8, 9, 32, 24, 8, 1)], 4, 1_024)
                .expect_err("emitted diagnostics cannot exceed candidates"),
            CudaDiagnosticAggregationError::EmittedExceedsCandidates {
                shard: 2,
                emitted_diagnostics: 9,
                candidate_items: 8,
            }
        );
        assert_eq!(
            plan_cuda_device_diagnostic_aggregation(&[shard(3, 8, 1, 32, 24, 8, 0)], 4, 1_024)
                .expect_err("diagnostics must retain class mask"),
            CudaDiagnosticAggregationError::MissingSeverityMask { shard: 3 }
        );
        assert_eq!(
            plan_cuda_device_diagnostic_aggregation(&[shard(4, 8, 1, 32, 24, 8, 1)], 4, 16)
                .expect_err("over budget plan should fail"),
            CudaDiagnosticAggregationError::OverBudget {
                required_bytes: 32,
                budget_bytes: 16,
            }
        );
    }

    #[test]
    fn diagnostic_aggregation_avoids_tree_sets_and_shard_vector_copies() {
        let src = include_str!("device_diagnostic_aggregation.rs");
        assert!(
            !src.contains(concat!("BTree", "Set")),
            "Fix: CUDA diagnostic aggregation should hash shard ids and sort compact-readback indices once."
        );
        assert!(
            !src.contains(concat!("shards", ".to_vec()")),
            "Fix: CUDA diagnostic aggregation should not copy all shard records before final compact-range ordering."
        );
        assert!(
            !src.contains(concat!(".", "saturating_sub")),
            "Fix: CUDA diagnostic aggregation avoided-readback accounting must be exact, not saturating."
        );
        assert!(
            src.contains("CudaDiagnosticAggregationScratch::try_with_capacity(shards.len())?"),
            "Fix: CUDA diagnostic aggregation must stage scratch with fallible release-path allocation."
        );
        assert!(
            src.contains("scratch.try_reserve_shards(shards.len())?"),
            "Fix: caller-owned CUDA diagnostic aggregation scratch must grow through fallible reservation."
        );
        assert!(
            src.contains("fn reserve_vec<T>("),
            "Fix: CUDA diagnostic aggregation result vectors must use typed fallible reservation."
        );
        assert!(
            src.contains("fn reserve_set<T>("),
            "Fix: CUDA diagnostic aggregation duplicate detection must use typed fallible reservation."
        );
        assert!(
            src.contains("StorageReserveFailed"),
            "Fix: CUDA diagnostic aggregation allocation failures must surface as actionable launch-planning errors."
        );
        assert!(
            !src.contains(concat!("FxHashSet::with_capacity", "_and_hasher")),
            "Fix: CUDA diagnostic aggregation scratch hash storage must not allocate infallibly."
        );
        assert!(
            !src.contains(concat!("Vec::with_capacity", "(shard_count)")),
            "Fix: CUDA diagnostic aggregation scratch vectors must not allocate infallibly."
        );
        assert!(
            !src.contains(concat!("Vec::with_capacity", "(shards.len())")),
            "Fix: CUDA diagnostic aggregation compact ranges must not allocate infallibly."
        );
        assert!(
            !src.contains(concat!("scratch.ids", ".reserve(shards.len())")),
            "Fix: CUDA diagnostic aggregation duplicate scratch must not grow infallibly."
        );
        assert!(
            !src.contains(concat!("scratch.ordered_indices", ".reserve(shards.len())")),
            "Fix: CUDA diagnostic aggregation ordering scratch must not grow infallibly."
        );
    }

    #[test]
    fn diagnostic_aggregation_reuses_caller_owned_shard_planning_scratch() {
        let mut scratch =
            CudaDiagnosticAggregationScratch::try_with_capacity(128).expect("scratch capacity");
        let wide = (0..128)
            .rev()
            .map(|index| shard(index, 1_024, 1, 32, 16, 8, 1))
            .collect::<Vec<_>>();
        let first =
            plan_cuda_device_diagnostic_aggregation_with_scratch(&wide, 4, 1 << 20, &mut scratch)
                .expect("wide diagnostic aggregation should plan with reusable scratch");
        let id_capacity = scratch.id_capacity();
        let ordered_index_capacity = scratch.ordered_index_capacity();

        assert_eq!(first.compact_ranges.len(), 128);
        assert_eq!(first.compact_ranges[0].shard, 0);

        let second = plan_cuda_device_diagnostic_aggregation_with_scratch(
            &[
                shard(9, 1_000, 0, 32, 24, 16, 0),
                shard(3, 1_000, 7, 32, 24, 16, 1),
            ],
            3,
            1 << 20,
            &mut scratch,
        )
        .expect("smaller diagnostic aggregation should reuse previous scratch");

        assert_eq!(second.compact_ranges[0].shard, 3);
        assert_eq!(second.overflow_records, 4);
        assert!(scratch.id_capacity() >= id_capacity);
        assert!(scratch.ordered_index_capacity() >= ordered_index_capacity);

        let src = include_str!("device_diagnostic_aggregation.rs");
        assert!(
            src.contains("pub fn plan_cuda_device_diagnostic_aggregation_with_scratch"),
            "Fix: release callers need a scratch-aware CUDA diagnostic aggregation planning path"
        );
        assert!(
            src.contains("scratch.ordered_indices.sort_unstable_by_key"),
            "Fix: CUDA diagnostic aggregation should sort retained shard indices in place"
        );
    }

    fn shard(
        shard: u32,
        candidate_items: u64,
        emitted_diagnostics: u64,
        raw_item_bytes: u64,
        diagnostic_record_bytes: u64,
        counter_bytes: u64,
        severity_mask: u32,
    ) -> CudaDiagnosticShard {
        CudaDiagnosticShard {
            shard,
            candidate_items,
            emitted_diagnostics,
            raw_item_bytes,
            diagnostic_record_bytes,
            counter_bytes,
            severity_mask,
        }
    }

    #[test]
    fn diagnostic_aggregation_production_ratio_path_does_not_panic() {
        let source = include_str!("device_diagnostic_aggregation.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("diagnostic aggregation source must contain production section");
        assert!(
            !production.contains(".expect(")
                && !production.contains(concat!("panic", "!("))
                && !production.contains(".unwrap_or_else("),
            "Fix: CUDA diagnostic aggregation production planning must return errors or bounded telemetry instead of panicking."
        );
        assert_eq!(
            compression_ratio_bps(u64::MAX, 1),
            u32::MAX,
            "Fix: diagnostic compression telemetry must remain bounded when a pathological ratio exceeds export width."
        );
    }
}
