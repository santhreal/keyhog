//! CUDA compact result readback planning.

use rustc_hash::FxHashSet;
use std::hash::Hash;

/// One CUDA output slot before result compaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaResultSlot {
    /// Stable output slot id.
    pub slot: u32,
    /// Meaningful bytes produced by the kernel.
    pub meaningful_bytes: u64,
    /// Allocated/readback capacity for the output slot.
    pub capacity_bytes: u64,
}

/// One compact readback record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaCompactResultRecord {
    /// Source output slot id.
    pub slot: u32,
    /// Offset in the compact readback slab.
    pub compact_offset: u64,
    /// Meaningful bytes copied into the slab.
    pub bytes: u64,
}

/// Compact result readback plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CudaResultCompactionPlan {
    /// Records copied into the compact slab.
    pub compact_records: Vec<CudaCompactResultRecord>,
    /// Output slots left as direct readback ranges.
    pub direct_slots: Vec<u32>,
    /// Total allocated/readback capacity across all output slots.
    pub full_capacity_bytes: u64,
    /// Total compact slab bytes.
    pub compact_bytes: u64,
    /// Total direct readback bytes.
    pub direct_bytes: u64,
    /// Total bytes actually selected for readback after compaction planning.
    pub selected_readback_bytes: u64,
    /// Bytes avoided compared with reading full output capacities.
    pub avoided_readback_bytes: u64,
    /// Avoided readback as floor basis points of full capacity.
    pub avoided_readback_basis_points: u32,
}

/// Caller-owned scratch for repeated CUDA result-compaction planning.
#[derive(Debug, Default)]
pub struct CudaResultCompactionScratch {
    ids: FxHashSet<u32>,
    ordered_indices: Vec<usize>,
}

impl CudaResultCompactionScratch {
    /// Allocate empty reusable compaction scratch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate reusable compaction scratch for a known output-slot count.
    pub fn try_with_capacity(slot_count: usize) -> Result<Self, CudaResultCompactionError> {
        let mut scratch = Self::default();
        scratch.try_reserve_slots(slot_count)?;
        Ok(scratch)
    }

    /// Reserve reusable compaction scratch for a known output-slot count.
    pub fn try_reserve_slots(
        &mut self,
        slot_count: usize,
    ) -> Result<(), CudaResultCompactionError> {
        reserve_set(&mut self.ids, slot_count, "scratch.ids")?;
        reserve_vec(
            &mut self.ordered_indices,
            slot_count,
            "scratch.ordered_indices",
        )
    }

    /// Retained duplicate-detection capacity.
    #[must_use]
    pub fn id_capacity(&self) -> usize {
        self.ids.capacity()
    }

    /// Retained slot-ordering capacity.
    #[must_use]
    pub fn ordered_index_capacity(&self) -> usize {
        self.ordered_indices.capacity()
    }
}

/// Result compaction errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CudaResultCompactionError {
    /// Duplicate output slot id.
    DuplicateSlot {
        /// Duplicate slot.
        slot: u32,
    },
    /// Meaningful bytes exceed allocated slot capacity.
    MeaningfulExceedsCapacity {
        /// Output slot.
        slot: u32,
        /// Meaningful bytes.
        meaningful_bytes: u64,
        /// Slot capacity.
        capacity_bytes: u64,
    },
    /// Byte arithmetic overflowed.
    ByteCountOverflow {
        /// Field being computed.
        field: &'static str,
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

impl std::fmt::Display for CudaResultCompactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateSlot { slot } => write!(
                f,
                "CUDA result compaction received duplicate output slot {slot}. Fix: assign unique output slots before readback planning."
            ),
            Self::MeaningfulExceedsCapacity {
                slot,
                meaningful_bytes,
                capacity_bytes,
            } => write!(
                f,
                "CUDA result slot {slot} has meaningful_bytes={meaningful_bytes} above capacity_bytes={capacity_bytes}. Fix: compute compact result sizes before dispatch readback."
            ),
            Self::ByteCountOverflow { field } => write!(
                f,
                "CUDA result compaction overflowed while computing {field}. Fix: shard compact result readback before launch."
            ),
            Self::StorageReserveFailed {
                field,
                requested,
                message,
            } => write!(
                f,
                "CUDA result compaction failed to reserve {field} for {requested} entries: {message}. Fix: shard result readback planning before launch."
            ),
        }
    }
}

impl std::error::Error for CudaResultCompactionError {}

/// Plan compact readback for small CUDA outputs.
pub fn plan_cuda_result_compaction(
    slots: &[CudaResultSlot],
    max_compact_record_bytes: u64,
) -> Result<CudaResultCompactionPlan, CudaResultCompactionError> {
    let mut scratch = CudaResultCompactionScratch::try_with_capacity(slots.len())?;
    plan_cuda_result_compaction_with_scratch(slots, max_compact_record_bytes, &mut scratch)
}

/// Plan compact readback using caller-owned temporary storage.
pub fn plan_cuda_result_compaction_with_scratch(
    slots: &[CudaResultSlot],
    max_compact_record_bytes: u64,
    scratch: &mut CudaResultCompactionScratch,
) -> Result<CudaResultCompactionPlan, CudaResultCompactionError> {
    scratch.ids.clear();
    scratch.ordered_indices.clear();
    scratch.try_reserve_slots(slots.len())?;
    let mut full_capacity_bytes = 0_u64;
    let mut compact_record_count = 0usize;
    let mut direct_slot_count = 0usize;

    for (index, slot) in slots.iter().copied().enumerate() {
        if !scratch.ids.insert(slot.slot) {
            return Err(CudaResultCompactionError::DuplicateSlot { slot: slot.slot });
        }
        if slot.meaningful_bytes > slot.capacity_bytes {
            return Err(CudaResultCompactionError::MeaningfulExceedsCapacity {
                slot: slot.slot,
                meaningful_bytes: slot.meaningful_bytes,
                capacity_bytes: slot.capacity_bytes,
            });
        }
        full_capacity_bytes = checked_add(
            full_capacity_bytes,
            slot.capacity_bytes,
            "full capacity bytes",
        )?;
        if slot.meaningful_bytes != 0 {
            if slot.meaningful_bytes <= max_compact_record_bytes {
                compact_record_count =
                    checked_add_usize(compact_record_count, 1, "compact record count")?;
            } else {
                direct_slot_count = checked_add_usize(direct_slot_count, 1, "direct slot count")?;
            }
        }
        scratch.ordered_indices.push(index);
    }
    scratch
        .ordered_indices
        .sort_unstable_by_key(|&index| slots[index].slot);

    let mut compact_records = reserved_vec(compact_record_count, "compact_records")?;
    let mut direct_slots = reserved_vec(direct_slot_count, "direct_slots")?;
    let mut compact_bytes = 0_u64;
    let mut direct_bytes = 0_u64;

    for &index in &scratch.ordered_indices {
        let slot = slots[index];
        if slot.meaningful_bytes == 0 {
            continue;
        }
        if slot.meaningful_bytes <= max_compact_record_bytes {
            compact_records.push(CudaCompactResultRecord {
                slot: slot.slot,
                compact_offset: compact_bytes,
                bytes: slot.meaningful_bytes,
            });
            compact_bytes = checked_add(compact_bytes, slot.meaningful_bytes, "compact bytes")?;
        } else {
            direct_slots.push(slot.slot);
            direct_bytes = checked_add(direct_bytes, slot.meaningful_bytes, "direct bytes")?;
        }
    }

    let selected_readback_bytes =
        checked_add(compact_bytes, direct_bytes, "selected readback bytes")?;

    let avoided_readback_bytes = checked_sub(
        full_capacity_bytes,
        selected_readback_bytes,
        "avoided readback bytes",
    )?;

    Ok(CudaResultCompactionPlan {
        compact_records,
        direct_slots,
        full_capacity_bytes,
        compact_bytes,
        direct_bytes,
        selected_readback_bytes,
        avoided_readback_bytes,
        avoided_readback_basis_points: ratio_basis_points(
            avoided_readback_bytes,
            full_capacity_bytes,
        ),
    })
}

fn checked_add(lhs: u64, rhs: u64, field: &'static str) -> Result<u64, CudaResultCompactionError> {
    lhs.checked_add(rhs)
        .ok_or(CudaResultCompactionError::ByteCountOverflow { field })
}

fn checked_sub(lhs: u64, rhs: u64, field: &'static str) -> Result<u64, CudaResultCompactionError> {
    lhs.checked_sub(rhs)
        .ok_or(CudaResultCompactionError::ByteCountOverflow { field })
}

fn checked_add_usize(
    lhs: usize,
    rhs: usize,
    field: &'static str,
) -> Result<usize, CudaResultCompactionError> {
    lhs.checked_add(rhs)
        .ok_or(CudaResultCompactionError::ByteCountOverflow { field })
}

fn ratio_basis_points(part: u64, whole: u64) -> u32 {
    if whole == 0 {
        return 0;
    }
    ((u128::from(part) * 10_000) / u128::from(whole)) as u32
}

fn reserve_vec<T>(
    vec: &mut Vec<T>,
    capacity: usize,
    field: &'static str,
) -> Result<(), CudaResultCompactionError> {
    if vec.capacity() >= capacity {
        return Ok(());
    }
    let additional = capacity - vec.capacity();
    vec.try_reserve_exact(additional).map_err(|error| {
        CudaResultCompactionError::StorageReserveFailed {
            field,
            requested: capacity,
            message: error.to_string(),
        }
    })
}

fn reserved_vec<T>(
    capacity: usize,
    field: &'static str,
) -> Result<Vec<T>, CudaResultCompactionError> {
    let mut vec = Vec::new();
    reserve_vec(&mut vec, capacity, field)?;
    Ok(vec)
}

fn reserve_set<T>(
    set: &mut FxHashSet<T>,
    capacity: usize,
    field: &'static str,
) -> Result<(), CudaResultCompactionError>
where
    T: Eq + Hash,
{
    if set.capacity() >= capacity {
        return Ok(());
    }
    let additional = capacity - set.capacity();
    set.try_reserve(additional)
        .map_err(|error| CudaResultCompactionError::StorageReserveFailed {
            field,
            requested: capacity,
            message: error.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_compaction_packs_small_outputs_and_skips_empty_slots() {
        let plan =
            plan_cuda_result_compaction(&[slot(2, 0, 128), slot(1, 12, 128), slot(3, 24, 256)], 32)
                .expect("small outputs should compact");

        assert_eq!(
            plan.compact_records,
            vec![
                CudaCompactResultRecord {
                    slot: 1,
                    compact_offset: 0,
                    bytes: 12,
                },
                CudaCompactResultRecord {
                    slot: 3,
                    compact_offset: 12,
                    bytes: 24,
                },
            ]
        );
        assert_eq!(plan.direct_slots, Vec::<u32>::new());
        assert_eq!(plan.full_capacity_bytes, 512);
        assert_eq!(plan.compact_bytes, 36);
        assert_eq!(plan.direct_bytes, 0);
        assert_eq!(plan.selected_readback_bytes, 36);
        assert_eq!(plan.avoided_readback_bytes, 476);
        assert_eq!(plan.avoided_readback_basis_points, 9_296);
    }

    #[test]
    fn result_compaction_keeps_large_outputs_direct() {
        let plan = plan_cuda_result_compaction(&[slot(1, 64, 128), slot(2, 512, 1_024)], 128)
            .expect("mixed outputs should plan");

        assert_eq!(plan.compact_records.len(), 1);
        assert_eq!(plan.direct_slots, vec![2]);
        assert_eq!(plan.full_capacity_bytes, 1_152);
        assert_eq!(plan.compact_bytes, 64);
        assert_eq!(plan.direct_bytes, 512);
        assert_eq!(plan.selected_readback_bytes, 576);
        assert_eq!(plan.avoided_readback_bytes, 576);
        assert_eq!(plan.avoided_readback_basis_points, 5_000);
    }

    #[test]
    fn result_compaction_reports_zero_work_telemetry_without_division() {
        let plan = plan_cuda_result_compaction(&[slot(4, 0, 0), slot(9, 0, 0)], 128)
            .expect("zero-capacity outputs should plan");

        assert!(plan.compact_records.is_empty());
        assert!(plan.direct_slots.is_empty());
        assert_eq!(plan.full_capacity_bytes, 0);
        assert_eq!(plan.compact_bytes, 0);
        assert_eq!(plan.direct_bytes, 0);
        assert_eq!(plan.selected_readback_bytes, 0);
        assert_eq!(plan.avoided_readback_bytes, 0);
        assert_eq!(plan.avoided_readback_basis_points, 0);
    }

    #[test]
    fn result_compaction_rejects_invalid_slots() {
        assert_eq!(
            plan_cuda_result_compaction(&[slot(1, 1, 8), slot(1, 1, 8)], 4)
                .expect_err("duplicate slots should fail"),
            CudaResultCompactionError::DuplicateSlot { slot: 1 }
        );
        assert_eq!(
            plan_cuda_result_compaction(&[slot(2, 9, 8)], 4)
                .expect_err("meaningful bytes above capacity should fail"),
            CudaResultCompactionError::MeaningfulExceedsCapacity {
                slot: 2,
                meaningful_bytes: 9,
                capacity_bytes: 8,
            }
        );
    }

    #[test]
    fn result_compaction_avoids_tree_sets_and_slot_vector_copies() {
        let src = include_str!("result_compaction.rs");
        assert!(
            !src.contains(concat!("BTree", "Set")),
            "Fix: CUDA result compaction duplicate detection should use a hash set; slot ordering should be a final index sort."
        );
        assert!(
            !src.contains(concat!("slots", ".to_vec()")),
            "Fix: CUDA result compaction should sort slot indices rather than copying every slot before planning readback."
        );
        assert!(
            !src.contains(concat!(".", "saturating_sub")),
            "Fix: CUDA result compaction avoided-readback accounting must be exact, not saturating."
        );
        assert!(
            !src.contains(concat!(" as ", "f32")) && !src.contains(concat!(" as ", "f64")),
            "Fix: CUDA result compaction efficiency telemetry must use integer arithmetic, not lossy floats."
        );
        assert!(
            src.contains("pub full_capacity_bytes: u64"),
            "Fix: CUDA result compaction plans must expose full-capacity telemetry from the checked accounting path."
        );
        assert!(
            src.contains("pub selected_readback_bytes: u64"),
            "Fix: CUDA result compaction plans must expose selected-readback telemetry from the checked accounting path."
        );
        assert!(
            src.contains("pub avoided_readback_basis_points: u32"),
            "Fix: CUDA result compaction plans must expose integer readback-reduction telemetry."
        );
        assert!(
            src.contains("CudaResultCompactionScratch::try_with_capacity(slots.len())?"),
            "Fix: CUDA result compaction must stage scratch with fallible release-path allocation."
        );
        assert!(
            src.contains("scratch.try_reserve_slots(slots.len())?"),
            "Fix: caller-owned CUDA result compaction scratch must grow through fallible reservation."
        );
        assert!(
            src.contains("fn reserve_vec<T>("),
            "Fix: CUDA result compaction result vectors must use typed fallible reservation."
        );
        assert!(
            src.contains("fn reserve_set<T>("),
            "Fix: CUDA result compaction duplicate detection must use typed fallible reservation."
        );
        assert!(
            src.contains("StorageReserveFailed"),
            "Fix: CUDA result compaction allocation failures must surface as actionable launch-planning errors."
        );
        assert!(
            !src.contains(concat!("FxHashSet::with_capacity", "_and_hasher")),
            "Fix: CUDA result compaction scratch hash storage must not allocate infallibly."
        );
        assert!(
            !src.contains(concat!("Vec::with_capacity", "(slot_count)")),
            "Fix: CUDA result compaction scratch vectors must not allocate infallibly."
        );
        assert!(
            !src.contains(concat!("Vec::with_capacity", "(slots.len())")),
            "Fix: CUDA result compaction result vectors must not allocate infallibly."
        );
        assert!(
            !src.contains(concat!("scratch.ids", ".reserve(slots.len())")),
            "Fix: CUDA result compaction duplicate scratch must not grow infallibly."
        );
        assert!(
            !src.contains(concat!("scratch.ordered_indices", ".reserve(slots.len())")),
            "Fix: CUDA result compaction ordering scratch must not grow infallibly."
        );
    }

    #[test]
    fn result_compaction_reuses_caller_owned_slot_planning_scratch() {
        let mut scratch =
            CudaResultCompactionScratch::try_with_capacity(96).expect("scratch capacity");
        let wide = (0..96)
            .rev()
            .map(|index| slot(index, 8, 64))
            .collect::<Vec<_>>();
        let first = plan_cuda_result_compaction_with_scratch(&wide, 16, &mut scratch)
            .expect("wide compact result set should plan with reusable scratch");
        let id_capacity = scratch.id_capacity();
        let ordered_index_capacity = scratch.ordered_index_capacity();

        assert_eq!(first.compact_records.len(), 96);
        assert_eq!(first.compact_records[0].slot, 0);

        let second = plan_cuda_result_compaction_with_scratch(
            &[slot(7, 0, 128), slot(3, 512, 1_024), slot(5, 16, 128)],
            32,
            &mut scratch,
        )
        .expect("smaller mixed result set should reuse previous scratch");

        assert_eq!(second.compact_records[0].slot, 5);
        assert_eq!(second.direct_slots, vec![3]);
        assert!(scratch.id_capacity() >= id_capacity);
        assert!(scratch.ordered_index_capacity() >= ordered_index_capacity);

        let src = include_str!("result_compaction.rs");
        assert!(
            src.contains("pub fn plan_cuda_result_compaction_with_scratch"),
            "Fix: release callers need a scratch-aware CUDA result compaction planning path"
        );
        assert!(
            src.contains("scratch.ordered_indices.sort_unstable_by_key"),
            "Fix: CUDA result compaction should sort retained slot indices in place"
        );
    }

    fn slot(slot: u32, meaningful_bytes: u64, capacity_bytes: u64) -> CudaResultSlot {
        CudaResultSlot {
            slot,
            meaningful_bytes,
            capacity_bytes,
        }
    }
}
