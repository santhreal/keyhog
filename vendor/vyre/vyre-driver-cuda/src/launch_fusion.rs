//! CUDA adjacent-stage launch fusion planning.

use rustc_hash::FxHashSet;

/// One adjacent CUDA stage considered for launch fusion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaFusionStage {
    /// Stable stage id.
    pub id: u32,
    /// Memory-layout compatibility hash.
    pub layout_hash: u64,
    /// Input bytes consumed by this stage.
    pub input_bytes: u64,
    /// Output bytes produced by this stage.
    pub output_bytes: u64,
    /// Scratch bytes required by this stage.
    pub scratch_bytes: u64,
    /// Whether this stage boundary requires host-visible materialization.
    pub requires_host_materialization: bool,
}

/// One fused adjacent-stage launch group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CudaLaunchFusionGroup {
    /// Stage ids included in the fused group.
    pub stage_ids: Vec<u32>,
    /// Shared layout hash for the group.
    pub layout_hash: u64,
    /// Peak bytes required by the fused group.
    pub required_bytes: u64,
    /// Host-visible intermediate bytes avoided by fusion.
    pub avoided_intermediate_bytes: u64,
}

/// Complete CUDA launch fusion plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CudaLaunchFusionPlan {
    /// Fused or singleton groups in original stage order.
    pub groups: Vec<CudaLaunchFusionGroup>,
    /// Number of CUDA launches after fusion.
    pub launch_count: u32,
    /// Number of launches removed by fusion.
    pub avoided_launches: u32,
    /// Total host-visible intermediate bytes avoided.
    pub avoided_intermediate_bytes: u64,
}

/// Caller-owned scratch for repeated CUDA launch-fusion planning.
#[derive(Debug, Default)]
pub struct CudaLaunchFusionScratch {
    ids: FxHashSet<u32>,
}

impl CudaLaunchFusionScratch {
    /// Create empty reusable launch-fusion scratch.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ids: FxHashSet::default(),
        }
    }

    /// Allocate reusable launch-fusion scratch for a known stage count.
    pub fn try_with_capacity(stage_count: usize) -> Result<Self, CudaLaunchFusionError> {
        let mut scratch = Self::new();
        scratch.try_reserve_ids(stage_count)?;
        Ok(scratch)
    }

    fn try_reserve_ids(&mut self, stage_count: usize) -> Result<(), CudaLaunchFusionError> {
        let additional = if self.ids.capacity() >= stage_count {
            0
        } else {
            stage_count - self.ids.capacity()
        };
        self.ids.try_reserve(additional).map_err(|error| {
            CudaLaunchFusionError::StorageReserveFailed {
                field: "duplicate stage ids",
                requested: stage_count,
                message: error.to_string(),
            }
        })
    }

    /// Retained duplicate-detection capacity.
    #[must_use]
    pub fn id_capacity(&self) -> usize {
        self.ids.capacity()
    }
}

/// CUDA launch fusion planning errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CudaLaunchFusionError {
    /// Duplicate stage id.
    DuplicateStage {
        /// Duplicate id.
        id: u32,
    },
    /// Explicit fusion budget cannot be zero.
    ZeroBudget,
    /// Byte arithmetic overflowed.
    ByteCountOverflow {
        /// Field being computed.
        field: &'static str,
    },
    /// One stage cannot fit the explicit fusion budget even without fusion.
    StageOverBudget {
        /// Stage id.
        id: u32,
        /// Required bytes for the singleton stage.
        required_bytes: u64,
        /// Caller-provided budget.
        budget_bytes: u64,
    },
    /// Planner storage could not be reserved.
    StorageReserveFailed {
        /// Field being reserved.
        field: &'static str,
        /// Number of entries requested.
        requested: usize,
        /// Allocator error text.
        message: String,
    },
}

impl std::fmt::Display for CudaLaunchFusionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateStage { id } => write!(
                f,
                "CUDA launch fusion received duplicate stage id {id}. Fix: emit unique stage ids before fusion planning."
            ),
            Self::ZeroBudget => write!(
                f,
                "CUDA launch fusion received a zero byte budget. Fix: pass an explicit device-memory budget before planning fusion."
            ),
            Self::ByteCountOverflow { field } => write!(
                f,
                "CUDA launch fusion overflowed while computing {field}. Fix: shard adjacent stages before launch fusion planning."
            ),
            Self::StageOverBudget {
                id,
                required_bytes,
                budget_bytes,
            } => write!(
                f,
                "CUDA launch fusion stage {id} requires {required_bytes} bytes but budget allows {budget_bytes}. Fix: shard the stage or raise the explicit fusion budget."
            ),
            Self::StorageReserveFailed {
                field,
                requested,
                message,
            } => write!(
                f,
                "CUDA launch fusion could not reserve {requested} {field} entries: {message}. Fix: shard adjacent stages before fusion planning."
            ),
        }
    }
}

impl std::error::Error for CudaLaunchFusionError {}

/// Plan adjacent CUDA launch fusion under layout and memory constraints.
pub fn plan_cuda_launch_fusion(
    stages: &[CudaFusionStage],
    max_group_bytes: u64,
) -> Result<CudaLaunchFusionPlan, CudaLaunchFusionError> {
    let mut scratch = CudaLaunchFusionScratch::try_with_capacity(stages.len())?;
    plan_cuda_launch_fusion_with_scratch(stages, max_group_bytes, &mut scratch)
}

/// Plan adjacent CUDA launch fusion using caller-owned temporary storage.
pub fn plan_cuda_launch_fusion_with_scratch(
    stages: &[CudaFusionStage],
    max_group_bytes: u64,
    scratch: &mut CudaLaunchFusionScratch,
) -> Result<CudaLaunchFusionPlan, CudaLaunchFusionError> {
    if max_group_bytes == 0 {
        return Err(CudaLaunchFusionError::ZeroBudget);
    }
    if stages.is_empty() {
        return Ok(CudaLaunchFusionPlan {
            groups: Vec::new(),
            launch_count: 0,
            avoided_launches: 0,
            avoided_intermediate_bytes: 0,
        });
    }
    if stages.len() == 1 {
        let group = singleton_group_with_capacity(stages[0], 1)?;
        if group.required_bytes > max_group_bytes {
            return Err(CudaLaunchFusionError::StageOverBudget {
                id: stages[0].id,
                required_bytes: group.required_bytes,
                budget_bytes: max_group_bytes,
            });
        }
        let mut groups = reserved_vec(1, "fusion groups")?;
        groups.push(group);
        return Ok(CudaLaunchFusionPlan {
            groups,
            launch_count: 1,
            avoided_launches: 0,
            avoided_intermediate_bytes: 0,
        });
    }
    scratch.ids.clear();
    if stages.len() <= 8 {
        for i in 0..stages.len() {
            let current = stages[i].id;
            if stages[..i].iter().any(|prev| prev.id == current) {
                return Err(CudaLaunchFusionError::DuplicateStage { id: current });
            }
        }
    } else {
        scratch.try_reserve_ids(stages.len())?;
        for stage in stages {
            if !scratch.ids.insert(stage.id) {
                return Err(CudaLaunchFusionError::DuplicateStage { id: stage.id });
            }
        }
    }

    let mut groups = reserved_vec(stages.len(), "fusion groups")?;
    let mut index = 0;
    while index < stages.len() {
        let remaining_stage_count = stages.len() - index;
        let mut group = singleton_group_with_capacity(stages[index], remaining_stage_count)?;
        if group.required_bytes > max_group_bytes {
            return Err(CudaLaunchFusionError::StageOverBudget {
                id: stages[index].id,
                required_bytes: group.required_bytes,
                budget_bytes: max_group_bytes,
            });
        }
        let mut cursor = index + 1;
        while cursor < stages.len() && can_append_to_group(&group, stages[cursor], max_group_bytes)?
        {
            let previous_output = stages[cursor - 1].output_bytes;
            group.required_bytes = fused_required_bytes(&group, stages[cursor])?;
            group.avoided_intermediate_bytes = checked_add(
                group.avoided_intermediate_bytes,
                previous_output,
                "avoided intermediate bytes",
            )?;
            group.stage_ids.push(stages[cursor].id);
            cursor += 1;
        }
        groups.push(group);
        index = cursor;
    }

    let launch_count =
        u32::try_from(groups.len()).map_err(|_| CudaLaunchFusionError::ByteCountOverflow {
            field: "launch count",
        })?;
    let avoided_launches = u32::try_from(stages.len() - groups.len()).map_err(|_| {
        CudaLaunchFusionError::ByteCountOverflow {
            field: "avoided launches",
        }
    })?;
    let mut avoided_intermediate_bytes = 0_u64;
    for group in &groups {
        avoided_intermediate_bytes = checked_add(
            avoided_intermediate_bytes,
            group.avoided_intermediate_bytes,
            "total avoided intermediate bytes",
        )?;
    }

    Ok(CudaLaunchFusionPlan {
        groups,
        launch_count,
        avoided_launches,
        avoided_intermediate_bytes,
    })
}

fn singleton_group_with_capacity(
    stage: CudaFusionStage,
    stage_id_capacity: usize,
) -> Result<CudaLaunchFusionGroup, CudaLaunchFusionError> {
    let mut stage_ids = reserved_vec(stage_id_capacity.max(1), "fusion group stage ids")?;
    stage_ids.push(stage.id);
    Ok(CudaLaunchFusionGroup {
        stage_ids,
        layout_hash: stage.layout_hash,
        required_bytes: stage_required_bytes(stage)?,
        avoided_intermediate_bytes: 0,
    })
}

fn can_append_to_group(
    group: &CudaLaunchFusionGroup,
    stage: CudaFusionStage,
    max_group_bytes: u64,
) -> Result<bool, CudaLaunchFusionError> {
    if stage.requires_host_materialization || stage.layout_hash != group.layout_hash {
        return Ok(false);
    }
    Ok(fused_required_bytes(group, stage)? <= max_group_bytes)
}

fn fused_required_bytes(
    group: &CudaLaunchFusionGroup,
    stage: CudaFusionStage,
) -> Result<u64, CudaLaunchFusionError> {
    checked_add(
        group.required_bytes,
        stage.scratch_bytes,
        "fused scratch bytes",
    )
    .and_then(|bytes| checked_add(bytes, stage.output_bytes, "fused output bytes"))
}

fn stage_required_bytes(stage: CudaFusionStage) -> Result<u64, CudaLaunchFusionError> {
    let input_plus_output = checked_add(stage.input_bytes, stage.output_bytes, "stage io bytes")?;
    checked_add(
        input_plus_output,
        stage.scratch_bytes,
        "stage required bytes",
    )
}

fn checked_add(lhs: u64, rhs: u64, field: &'static str) -> Result<u64, CudaLaunchFusionError> {
    lhs.checked_add(rhs)
        .ok_or(CudaLaunchFusionError::ByteCountOverflow { field })
}

fn reserve_vec<T>(
    vec: &mut Vec<T>,
    capacity: usize,
    field: &'static str,
) -> Result<(), CudaLaunchFusionError> {
    let additional = if vec.capacity() >= capacity {
        0
    } else {
        capacity - vec.capacity()
    };
    vec.try_reserve_exact(additional)
        .map_err(|error| CudaLaunchFusionError::StorageReserveFailed {
            field,
            requested: capacity,
            message: error.to_string(),
        })
}

fn reserved_vec<T>(capacity: usize, field: &'static str) -> Result<Vec<T>, CudaLaunchFusionError> {
    let mut vec = Vec::new();
    reserve_vec(&mut vec, capacity, field)?;
    Ok(vec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_fusion_groups_adjacent_compatible_stages() {
        let plan = plan_cuda_launch_fusion(
            &[
                stage(1, 7, 64, 32, 8, false),
                stage(2, 7, 32, 48, 8, false),
                stage(3, 7, 48, 16, 8, false),
            ],
            256,
        )
        .expect("compatible stages should fuse");

        assert_eq!(plan.launch_count, 1);
        assert_eq!(plan.avoided_launches, 2);
        assert_eq!(plan.groups[0].stage_ids, vec![1, 2, 3]);
        assert_eq!(plan.avoided_intermediate_bytes, 80);
    }

    #[test]
    fn launch_fusion_splits_on_layout_host_boundary_and_budget() {
        let plan = plan_cuda_launch_fusion(
            &[
                stage(1, 7, 64, 32, 8, false),
                stage(2, 8, 32, 48, 8, false),
                stage(3, 8, 48, 16, 8, true),
                stage(4, 9, 16, 16, 8, false),
            ],
            128,
        )
        .expect("incompatible stages should split deterministically");

        assert_eq!(plan.launch_count, 4);
        assert_eq!(plan.avoided_launches, 0);
        assert_eq!(plan.groups[0].stage_ids, vec![1]);
        assert_eq!(plan.groups[1].stage_ids, vec![2]);
        assert_eq!(plan.groups[2].stage_ids, vec![3]);
        assert_eq!(plan.groups[3].stage_ids, vec![4]);
    }

    #[test]
    fn launch_fusion_rejects_invalid_inputs() {
        assert_eq!(
            plan_cuda_launch_fusion(&[stage(1, 7, 1, 1, 1, false)], 0)
                .expect_err("zero budget should fail"),
            CudaLaunchFusionError::ZeroBudget
        );
        assert_eq!(
            plan_cuda_launch_fusion(
                &[stage(1, 7, 1, 1, 1, false), stage(1, 7, 1, 1, 1, false),],
                128,
            )
            .expect_err("duplicate stages should fail"),
            CudaLaunchFusionError::DuplicateStage { id: 1 }
        );
        assert_eq!(
            plan_cuda_launch_fusion(&[stage(9, 7, 64, 32, 64, false)], 128)
                .expect_err("single over-budget stage should fail"),
            CudaLaunchFusionError::StageOverBudget {
                id: 9,
                required_bytes: 160,
                budget_bytes: 128,
            }
        );
    }

    #[test]
    fn launch_fusion_duplicate_detection_avoids_ordered_tree_set() {
        let src = include_str!("launch_fusion.rs");
        assert!(
            !src.contains(concat!("BTree", "Set")),
            "Fix: CUDA launch fusion already preserves stage order from the input stream; duplicate detection should not pay ordered tree lookup cost."
        );
    }

    #[test]
    fn launch_fusion_reuses_caller_owned_duplicate_detection_scratch() {
        let mut scratch =
            CudaLaunchFusionScratch::try_with_capacity(64).expect("fusion scratch should reserve");
        let wide = (0..64)
            .map(|id| stage(id, 7, 16, 16, 4, false))
            .collect::<Vec<_>>();
        let first = plan_cuda_launch_fusion_with_scratch(&wide, 8_192, &mut scratch)
            .expect("wide compatible CUDA stages should fuse");
        let id_capacity = scratch.id_capacity();

        assert_eq!(first.launch_count, 1);
        assert_eq!(first.avoided_launches, 63);

        let second = plan_cuda_launch_fusion_with_scratch(
            &[
                stage(10, 7, 64, 32, 8, false),
                stage(11, 8, 32, 48, 8, false),
            ],
            512,
            &mut scratch,
        )
        .expect("smaller incompatible CUDA stages should reuse duplicate-detection scratch");

        assert_eq!(second.launch_count, 2);
        assert!(scratch.id_capacity() >= id_capacity);

        let src = include_str!("launch_fusion.rs");
        assert!(
            src.contains("pub fn plan_cuda_launch_fusion_with_scratch"),
            "Fix: release callers need a scratch-aware CUDA launch fusion planning path"
        );
        assert!(
            src.contains("scratch.try_reserve_ids(stages.len())?"),
            "Fix: CUDA launch fusion duplicate detection should reuse caller-owned hash storage with fallible reservation"
        );
    }

    #[test]
    fn launch_fusion_staging_reserves_fallibly() {
        let src = include_str!("launch_fusion.rs");

        assert!(
            src.contains("CudaLaunchFusionScratch::try_with_capacity(stages.len())?")
                && src.contains("scratch.try_reserve_ids(stages.len())?")
                && src.contains("fn reserve_vec<T>(")
                && src.contains("try_reserve_exact(additional)")
                && src.contains("StorageReserveFailed"),
            "Fix: CUDA launch fusion staging must use typed fallible reservations under scale pressure."
        );
        assert!(
            !src.contains(concat!("FxHashSet::with_capacity", "_and_hasher"))
                && !src.contains(concat!("Vec::with_capacity", "(stages.len())"))
                && !src.contains(concat!("groups: vec![", "group]"))
                && !src.contains(concat!("stage_ids: vec![", "stage.id]"))
                && !src.contains(concat!("scratch.ids", ".reserve(stages.len())")),
            "Fix: CUDA launch fusion release planning must not use infallible staging allocation."
        );
    }

    fn stage(
        id: u32,
        layout_hash: u64,
        input_bytes: u64,
        output_bytes: u64,
        scratch_bytes: u64,
        requires_host_materialization: bool,
    ) -> CudaFusionStage {
        CudaFusionStage {
            id,
            layout_hash,
            input_bytes,
            output_bytes,
            scratch_bytes,
            requires_host_materialization,
        }
    }
}
