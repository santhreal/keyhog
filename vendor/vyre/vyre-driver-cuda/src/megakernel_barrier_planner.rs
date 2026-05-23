//! CUDA megakernel barrier planning for dependency-typed dataflow waves.
//!
//! The planner is pure and deterministic: it converts a wave dependency DAG
//! into the minimum number of global-synchronization layers implied by those
//! dependencies. Waves inside one layer are independent and can be fused into
//! one cooperative megakernel phase without inserting a host-side barrier.

use crate::megakernel_plan_cache::{
    CudaMegakernelAnalysisKind, CudaMegakernelDeviceKey, CudaMegakernelPlanCache,
};
use crate::megakernel_scheduler::{
    CudaMegakernelExecutionPlan, CudaMegakernelGraphShape, CudaMegakernelMemoryError,
    CudaMegakernelScheduleSample,
};

/// Directed dependency between two CUDA megakernel dataflow waves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaMegakernelWaveDependency {
    /// Wave that must complete first.
    pub before: usize,
    /// Wave that can run after `before`.
    pub after: usize,
}

/// One barrier-free group of independent CUDA megakernel waves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CudaMegakernelBarrierGroup {
    /// Wave indices that can run before the next global synchronization point.
    pub waves: Vec<usize>,
}

/// Barrier plan for CUDA megakernel execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CudaMegakernelBarrierPlan {
    /// Ordered barrier-free wave groups.
    pub groups: Vec<CudaMegakernelBarrierGroup>,
    /// Number of global synchronization points required between groups.
    pub global_barriers: usize,
}

/// Caller-owned scratch for repeated CUDA megakernel barrier planning.
///
/// This keeps CSR adjacency, indegree, and ready-layer buffers reusable across
/// frontier-planning calls. Returned barrier groups still own their wave lists;
/// the scratch removes the temporary O(waves + dependencies) planning
/// allocations from steady-state callers.
#[derive(Debug, Default)]
pub struct CudaMegakernelBarrierScratch {
    outgoing_counts: Vec<usize>,
    indegree: Vec<usize>,
    outgoing_offsets: Vec<usize>,
    outgoing_targets: Vec<usize>,
    ready: Vec<usize>,
    next_ready: Vec<usize>,
}

impl CudaMegakernelBarrierScratch {
    /// Allocate reusable scratch for a known megakernel dependency shape,
    /// returning a typed planner error when the shape cannot be represented.
    pub fn try_with_capacity(
        wave_count: usize,
        dependency_count: usize,
    ) -> Result<Self, CudaMegakernelBarrierPlanError> {
        let mut scratch = Self::default();
        scratch.try_reserve_shape(wave_count, dependency_count)?;
        Ok(scratch)
    }

    fn try_reserve_shape(
        &mut self,
        wave_count: usize,
        dependency_count: usize,
    ) -> Result<(), CudaMegakernelBarrierPlanError> {
        let offset_capacity =
            wave_count
                .checked_add(1)
                .ok_or(CudaMegakernelBarrierPlanError::ByteCountOverflow {
                    field: "barrier scratch wave offsets",
                })?;
        reserve_barrier_vec(&mut self.outgoing_counts, wave_count, "outgoing counts")?;
        reserve_barrier_vec(&mut self.indegree, wave_count, "indegree")?;
        reserve_barrier_vec(
            &mut self.outgoing_offsets,
            offset_capacity,
            "outgoing offsets",
        )?;
        reserve_barrier_vec(
            &mut self.outgoing_targets,
            dependency_count,
            "outgoing targets",
        )?;
        reserve_barrier_vec(&mut self.ready, wave_count, "ready wave layer")?;
        reserve_barrier_vec(&mut self.next_ready, wave_count, "next ready wave layer")?;
        Ok(())
    }

    /// Retained wave-index capacity across CSR planning buffers.
    #[must_use]
    pub fn wave_capacity(&self) -> usize {
        let offset_wave_capacity = if self.outgoing_offsets.capacity() == 0 {
            0
        } else {
            self.outgoing_offsets.capacity() - 1
        };
        self.outgoing_counts
            .capacity()
            .min(self.indegree.capacity())
            .min(offset_wave_capacity)
    }

    /// Retained dependency-edge capacity for CSR adjacency targets.
    #[must_use]
    pub fn dependency_capacity(&self) -> usize {
        self.outgoing_targets.capacity()
    }
}

/// Frontier-typed CUDA megakernel wave memory envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaMegakernelFrontierWave {
    /// Resident frontier bytes touched by this wave.
    pub frontier_bytes: u64,
    /// Temporary scratch bytes required by this wave before topology scaling.
    pub scratch_bytes: u64,
    /// Output bytes produced by this wave.
    pub output_bytes: u64,
}

/// Dependency-aware CUDA megakernel execution plan for frontier waves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CudaMegakernelFrontierExecutionPlan {
    /// Cache-backed topology and memory-budget plan.
    pub execution: CudaMegakernelExecutionPlan,
    /// Minimum global-barrier grouping for the wave dependencies.
    pub barriers: CudaMegakernelBarrierPlan,
    /// Peak frontier bytes across any fused barrier-free group.
    pub peak_frontier_bytes: u64,
    /// Peak scratch bytes across any fused barrier-free group.
    pub peak_scratch_bytes: u64,
    /// Peak output bytes across any fused barrier-free group.
    pub peak_output_bytes: u64,
    /// Readback pressure fed into topology selection after combining runtime
    /// telemetry with static fused-wave output volume.
    pub amortized_readback_bytes: u64,
    /// Widest barrier-free group in wave count.
    pub max_group_width: usize,
}

/// Barrier planning failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CudaMegakernelBarrierPlanError {
    /// A dependency references a wave outside `0..wave_count`.
    InvalidWave {
        /// Declared number of waves.
        wave_count: usize,
        /// Invalid `before` endpoint.
        before: usize,
        /// Invalid `after` endpoint.
        after: usize,
    },
    /// A wave was declared to depend on itself.
    SelfDependency {
        /// Self-dependent wave index.
        wave: usize,
    },
    /// The dependency graph contains a cycle and cannot be scheduled.
    Cycle {
        /// Number of waves that could not be scheduled.
        unscheduled_waves: usize,
    },
    /// Dependency CSR arithmetic overflowed.
    ByteCountOverflow {
        /// Field being computed.
        field: &'static str,
    },
    /// Planner scratch/result storage could not be reserved.
    StorageReserveFailed {
        /// Field being reserved.
        field: &'static str,
        /// Number of elements requested.
        requested: usize,
        /// Allocator error text.
        message: String,
    },
}

/// Dependency-aware frontier execution planning failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CudaMegakernelFrontierExecutionPlanError {
    /// Dependency graph cannot be barrier-planned.
    Barrier(CudaMegakernelBarrierPlanError),
    /// Peak wave bytes overflowed while grouping a barrier-free phase.
    ByteCountOverflow {
        /// Field being accumulated.
        field: &'static str,
    },
    /// Static graph or fused frontier bytes exceed the caller-approved budget.
    GroupOverBudget {
        /// Required bytes before topology selection.
        required_bytes: u64,
        /// Caller-provided budget.
        budget_bytes: u64,
        /// Budget region being checked.
        field: &'static str,
    },
    /// Cache-backed execution memory planning failed.
    Memory(CudaMegakernelMemoryError),
    /// Frontier planning result storage could not be reserved.
    StorageReserveFailed {
        /// Field being reserved.
        field: &'static str,
        /// Number of elements requested.
        requested: usize,
        /// Allocator error text.
        message: String,
    },
}

impl std::fmt::Display for CudaMegakernelBarrierPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidWave {
                wave_count,
                before,
                after,
            } => write!(
                f,
                "CUDA megakernel dependency references invalid wave before={before} after={after} for wave_count={wave_count}. Fix: emit dependencies only over normalized wave indices."
            ),
            Self::SelfDependency { wave } => write!(
                f,
                "CUDA megakernel wave {wave} depends on itself. Fix: remove the self-edge or split the wave into distinct producer/consumer phases."
            ),
            Self::Cycle { unscheduled_waves } => write!(
                f,
                "CUDA megakernel wave dependency graph contains a cycle with {unscheduled_waves} unscheduled waves. Fix: break the cyclic dataflow edge or insert an explicit iterative fixed-point kernel."
            ),
            Self::ByteCountOverflow { field } => write!(
                f,
                "CUDA megakernel barrier planner overflowed while computing {field}. Fix: shard the dependency graph before barrier planning."
            ),
            Self::StorageReserveFailed {
                field,
                requested,
                message,
            } => write!(
                f,
                "CUDA megakernel barrier planner could not reserve {requested} {field} entries: {message}. Fix: shard the dependency graph before barrier planning."
            ),
        }
    }
}

impl std::error::Error for CudaMegakernelBarrierPlanError {}

impl std::fmt::Display for CudaMegakernelFrontierExecutionPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Barrier(error) => error.fmt(f),
            Self::ByteCountOverflow { field } => write!(
                f,
                "CUDA megakernel frontier execution planner overflowed while accumulating {field}. Fix: shard the frontier wave group or split the fused phase."
            ),
            Self::GroupOverBudget {
                required_bytes,
                budget_bytes,
                field,
            } => write!(
                f,
                "CUDA megakernel frontier execution planner requires {required_bytes} bytes for {field} but budget allows {budget_bytes}. Fix: shard the graph/frontier waves or raise the explicit CUDA megakernel budget."
            ),
            Self::Memory(error) => error.fmt(f),
            Self::StorageReserveFailed {
                field,
                requested,
                message,
            } => write!(
                f,
                "CUDA megakernel frontier execution planner could not reserve {requested} {field} entries: {message}. Fix: shard the frontier waves before planning."
            ),
        }
    }
}

impl std::error::Error for CudaMegakernelFrontierExecutionPlanError {}

impl From<CudaMegakernelBarrierPlanError> for CudaMegakernelFrontierExecutionPlanError {
    fn from(error: CudaMegakernelBarrierPlanError) -> Self {
        Self::Barrier(error)
    }
}

impl From<CudaMegakernelMemoryError> for CudaMegakernelFrontierExecutionPlanError {
    fn from(error: CudaMegakernelMemoryError) -> Self {
        Self::Memory(error)
    }
}

/// Plan minimum global barriers for a CUDA megakernel wave dependency DAG.
///
/// The returned groups are Kahn topological layers. That is the minimum number
/// of dependency-implied execution rounds for a DAG when every ready wave may
/// execute in the same cooperative phase.
pub fn plan_cuda_megakernel_barriers(
    wave_count: usize,
    dependencies: &[CudaMegakernelWaveDependency],
) -> Result<CudaMegakernelBarrierPlan, CudaMegakernelBarrierPlanError> {
    let mut scratch =
        CudaMegakernelBarrierScratch::try_with_capacity(wave_count, dependencies.len())?;
    plan_cuda_megakernel_barriers_with_scratch(wave_count, dependencies, &mut scratch)
}

/// Plan minimum global barriers using caller-owned temporary storage.
pub fn plan_cuda_megakernel_barriers_with_scratch(
    wave_count: usize,
    dependencies: &[CudaMegakernelWaveDependency],
    scratch: &mut CudaMegakernelBarrierScratch,
) -> Result<CudaMegakernelBarrierPlan, CudaMegakernelBarrierPlanError> {
    scratch.try_reserve_shape(wave_count, dependencies.len())?;
    if wave_count == 0 {
        if !dependencies.is_empty() {
            return Err(CudaMegakernelBarrierPlanError::InvalidWave {
                wave_count,
                before: dependencies[0].before,
                after: dependencies[0].after,
            });
        }
        return Ok(CudaMegakernelBarrierPlan {
            global_barriers: 0,
            groups: Vec::new(),
        });
    }
    if dependencies.is_empty() {
        let mut waves = Vec::new();
        reserve_barrier_vec(&mut waves, wave_count, "independent wave group")?;
        for wave in 0..wave_count {
            waves.push(wave);
        }
        let mut groups = Vec::new();
        reserve_barrier_vec(&mut groups, 1, "barrier groups")?;
        groups.push(CudaMegakernelBarrierGroup { waves });
        return Ok(CudaMegakernelBarrierPlan {
            global_barriers: 0,
            groups,
        });
    }
    fill_barrier_vec_zeroed(&mut scratch.outgoing_counts, wave_count, "outgoing counts")?;
    fill_barrier_vec_zeroed(&mut scratch.indegree, wave_count, "indegree")?;
    for dependency in dependencies {
        if dependency.before >= wave_count || dependency.after >= wave_count {
            return Err(CudaMegakernelBarrierPlanError::InvalidWave {
                wave_count,
                before: dependency.before,
                after: dependency.after,
            });
        }
        if dependency.before == dependency.after {
            return Err(CudaMegakernelBarrierPlanError::SelfDependency {
                wave: dependency.before,
            });
        }
        scratch.outgoing_counts[dependency.before] = scratch.outgoing_counts[dependency.before]
            .checked_add(1)
            .ok_or(CudaMegakernelBarrierPlanError::ByteCountOverflow {
                field: "outgoing dependency count",
            })?;
        scratch.indegree[dependency.after] = scratch.indegree[dependency.after]
            .checked_add(1)
            .ok_or(CudaMegakernelBarrierPlanError::ByteCountOverflow {
                field: "incoming dependency count",
            })?;
    }
    scratch.outgoing_offsets.clear();
    scratch.outgoing_offsets.push(0usize);
    for count in &scratch.outgoing_counts {
        let next = scratch
            .outgoing_offsets
            .last()
            .copied()
            .ok_or(CudaMegakernelBarrierPlanError::ByteCountOverflow {
                field: "outgoing offset seed",
            })?
            .checked_add(*count)
            .ok_or(CudaMegakernelBarrierPlanError::ByteCountOverflow {
                field: "outgoing dependency offsets",
            })?;
        scratch.outgoing_offsets.push(next);
    }
    fill_barrier_vec_zeroed(
        &mut scratch.outgoing_targets,
        dependencies.len(),
        "outgoing targets",
    )?;
    scratch
        .outgoing_counts
        .copy_from_slice(&scratch.outgoing_offsets[..wave_count]);
    for dependency in dependencies {
        let offset = scratch.outgoing_counts[dependency.before];
        scratch.outgoing_targets[offset] = dependency.after;
        scratch.outgoing_counts[dependency.before] =
            offset
                .checked_add(1)
                .ok_or(CudaMegakernelBarrierPlanError::ByteCountOverflow {
                    field: "outgoing target cursor",
                })?;
    }

    scratch.ready.clear();
    for (wave, degree) in scratch.indegree.iter().copied().enumerate() {
        if degree == 0 {
            scratch.ready.push(wave);
        }
    }

    let mut scheduled = 0usize;
    let mut groups = Vec::new();
    reserve_barrier_vec(
        &mut groups,
        group_capacity_hint(wave_count, dependencies.len())?,
        "barrier groups",
    )?;
    scratch.next_ready.clear();
    while !scratch.ready.is_empty() {
        scratch.next_ready.clear();
        for &wave in &scratch.ready {
            for &next in &scratch.outgoing_targets
                [scratch.outgoing_offsets[wave]..scratch.outgoing_offsets[wave + 1]]
            {
                scratch.indegree[next] -= 1;
                if scratch.indegree[next] == 0 {
                    scratch.next_ready.push(next);
                }
            }
        }
        scheduled += scratch.ready.len();
        groups.push(CudaMegakernelBarrierGroup {
            waves: std::mem::take(&mut scratch.ready),
        });
        std::mem::swap(&mut scratch.ready, &mut scratch.next_ready);
    }

    if scheduled != wave_count {
        return Err(CudaMegakernelBarrierPlanError::Cycle {
            unscheduled_waves: wave_count - scheduled,
        });
    }

    Ok(CudaMegakernelBarrierPlan {
        global_barriers: if groups.is_empty() {
            0
        } else {
            groups.len() - 1
        },
        groups,
    })
}

fn group_capacity_hint(
    wave_count: usize,
    dependency_count: usize,
) -> Result<usize, CudaMegakernelBarrierPlanError> {
    if wave_count == 0 {
        Ok(0)
    } else {
        let dependency_layer_cap = dependency_count.checked_add(1).ok_or(
            CudaMegakernelBarrierPlanError::ByteCountOverflow {
                field: "barrier group capacity hint",
            },
        )?;
        Ok(wave_count.min(dependency_layer_cap))
    }
}

fn reserve_barrier_vec<T>(
    vec: &mut Vec<T>,
    capacity: usize,
    field: &'static str,
) -> Result<(), CudaMegakernelBarrierPlanError> {
    let additional = if vec.capacity() >= capacity {
        0
    } else {
        capacity - vec.capacity()
    };
    vec.try_reserve_exact(additional).map_err(|error| {
        CudaMegakernelBarrierPlanError::StorageReserveFailed {
            field,
            requested: capacity,
            message: error.to_string(),
        }
    })
}

fn fill_barrier_vec_zeroed(
    vec: &mut Vec<usize>,
    len: usize,
    field: &'static str,
) -> Result<(), CudaMegakernelBarrierPlanError> {
    vec.clear();
    reserve_barrier_vec(vec, len, field)?;
    vec.extend((0..len).map(|_| 0));
    Ok(())
}

/// Plan dependency-aware CUDA megakernel execution for frontier-typed waves.
///
/// The planner first minimizes global barriers from wave dependencies, then
/// computes the peak memory envelope of any barrier-free fused group, and
/// finally asks the CUDA plan cache for a memory-validated execution topology.
pub fn plan_cuda_frontier_megakernel_execution(
    cache: &mut CudaMegakernelPlanCache,
    graph_layout_hash: u64,
    analysis_kind: CudaMegakernelAnalysisKind,
    device: CudaMegakernelDeviceKey,
    sample: CudaMegakernelScheduleSample,
    graph: CudaMegakernelGraphShape,
    bytes_per_node: u64,
    bytes_per_edge: u64,
    waves: &[CudaMegakernelFrontierWave],
    dependencies: &[CudaMegakernelWaveDependency],
    budget_bytes: u64,
    launch_overhead_ns: f64,
    fusion_pressure: f64,
) -> Result<CudaMegakernelFrontierExecutionPlan, CudaMegakernelFrontierExecutionPlanError> {
    let mut scratch =
        CudaMegakernelBarrierScratch::try_with_capacity(waves.len(), dependencies.len())?;
    plan_cuda_frontier_megakernel_execution_with_scratch(
        cache,
        graph_layout_hash,
        analysis_kind,
        device,
        sample,
        graph,
        bytes_per_node,
        bytes_per_edge,
        waves,
        dependencies,
        budget_bytes,
        launch_overhead_ns,
        fusion_pressure,
        &mut scratch,
    )
}

/// Plan dependency-aware CUDA megakernel execution using caller-owned barrier scratch.
pub fn plan_cuda_frontier_megakernel_execution_with_scratch(
    cache: &mut CudaMegakernelPlanCache,
    graph_layout_hash: u64,
    analysis_kind: CudaMegakernelAnalysisKind,
    device: CudaMegakernelDeviceKey,
    sample: CudaMegakernelScheduleSample,
    graph: CudaMegakernelGraphShape,
    bytes_per_node: u64,
    bytes_per_edge: u64,
    waves: &[CudaMegakernelFrontierWave],
    dependencies: &[CudaMegakernelWaveDependency],
    budget_bytes: u64,
    launch_overhead_ns: f64,
    fusion_pressure: f64,
    scratch: &mut CudaMegakernelBarrierScratch,
) -> Result<CudaMegakernelFrontierExecutionPlan, CudaMegakernelFrontierExecutionPlanError> {
    let barriers = plan_cuda_megakernel_barriers_with_scratch(waves.len(), dependencies, scratch)?;
    let graph_bytes = graph_resident_bytes(graph, bytes_per_node, bytes_per_edge)?;
    let group_budget_bytes = budget_bytes.checked_sub(graph_bytes).ok_or(
        CudaMegakernelFrontierExecutionPlanError::GroupOverBudget {
            required_bytes: graph_bytes,
            budget_bytes,
            field: "resident graph bytes",
        },
    )?;
    let barriers = split_barrier_groups_to_memory_budget(barriers, waves, group_budget_bytes)?;
    let mut peak_frontier_bytes = 0u64;
    let mut peak_scratch_bytes = 0u64;
    let mut peak_output_bytes = 0u64;
    let mut max_group_width = 0usize;
    for group in &barriers.groups {
        let mut group_frontier_bytes = 0u64;
        let mut group_scratch_bytes = 0u64;
        let mut group_output_bytes = 0u64;
        max_group_width = max_group_width.max(group.waves.len());
        for &wave_index in &group.waves {
            let wave = waves[wave_index];
            group_frontier_bytes = checked_add(
                group_frontier_bytes,
                wave.frontier_bytes,
                "frontier wave bytes",
            )?;
            group_scratch_bytes = checked_add(
                group_scratch_bytes,
                wave.scratch_bytes,
                "scratch wave bytes",
            )?;
            group_output_bytes =
                checked_add(group_output_bytes, wave.output_bytes, "output wave bytes")?;
        }
        peak_frontier_bytes = peak_frontier_bytes.max(group_frontier_bytes);
        peak_scratch_bytes = peak_scratch_bytes.max(group_scratch_bytes);
        peak_output_bytes = peak_output_bytes.max(group_output_bytes);
    }

    let topology_sample = CudaMegakernelScheduleSample {
        readback_bytes: sample.readback_bytes.max(peak_output_bytes),
        ..sample
    };
    let execution = cache.get_or_plan_execution(
        graph_layout_hash,
        analysis_kind,
        device,
        topology_sample,
        graph,
        bytes_per_node,
        bytes_per_edge,
        peak_frontier_bytes,
        peak_scratch_bytes,
        peak_output_bytes,
        budget_bytes,
        launch_overhead_ns,
        fusion_pressure,
    )?;

    Ok(CudaMegakernelFrontierExecutionPlan {
        execution,
        barriers,
        peak_frontier_bytes,
        peak_scratch_bytes,
        peak_output_bytes,
        amortized_readback_bytes: topology_sample.readback_bytes,
        max_group_width,
    })
}

fn checked_add(
    lhs: u64,
    rhs: u64,
    field: &'static str,
) -> Result<u64, CudaMegakernelFrontierExecutionPlanError> {
    lhs.checked_add(rhs)
        .ok_or(CudaMegakernelFrontierExecutionPlanError::ByteCountOverflow { field })
}

fn checked_mul(
    lhs: u64,
    rhs: u64,
    field: &'static str,
) -> Result<u64, CudaMegakernelFrontierExecutionPlanError> {
    lhs.checked_mul(rhs)
        .ok_or(CudaMegakernelFrontierExecutionPlanError::ByteCountOverflow { field })
}

fn graph_resident_bytes(
    graph: CudaMegakernelGraphShape,
    bytes_per_node: u64,
    bytes_per_edge: u64,
) -> Result<u64, CudaMegakernelFrontierExecutionPlanError> {
    let node_bytes = checked_mul(graph.node_count, bytes_per_node, "node layout bytes")?;
    let edge_bytes = checked_mul(graph.edge_count, bytes_per_edge, "edge layout bytes")?;
    checked_add(node_bytes, edge_bytes, "graph layout bytes")
}

fn split_barrier_groups_to_memory_budget(
    barriers: CudaMegakernelBarrierPlan,
    waves: &[CudaMegakernelFrontierWave],
    group_budget_bytes: u64,
) -> Result<CudaMegakernelBarrierPlan, CudaMegakernelFrontierExecutionPlanError> {
    let mut groups = Vec::new();
    reserve_frontier_vec(&mut groups, barriers.groups.len(), "split barrier groups")?;
    for group in barriers.groups {
        split_one_barrier_group_to_memory_budget(group, waves, group_budget_bytes, &mut groups)?;
    }
    Ok(CudaMegakernelBarrierPlan {
        global_barriers: if groups.is_empty() {
            0
        } else {
            groups.len() - 1
        },
        groups,
    })
}

fn split_one_barrier_group_to_memory_budget(
    group: CudaMegakernelBarrierGroup,
    waves: &[CudaMegakernelFrontierWave],
    group_budget_bytes: u64,
    groups: &mut Vec<CudaMegakernelBarrierGroup>,
) -> Result<(), CudaMegakernelFrontierExecutionPlanError> {
    let mut current = Vec::new();
    reserve_frontier_vec(
        &mut current,
        group.waves.len().min(8),
        "current split barrier group",
    )?;
    let mut current_bytes = 0u64;
    for wave_index in group.waves {
        let wave_bytes = fused_wave_budget_bytes(waves[wave_index])?;
        let combined = checked_add(
            current_bytes,
            wave_bytes,
            "barrier group fused wave budget bytes",
        )?;
        if current.is_empty() && wave_bytes > group_budget_bytes {
            return Err(CudaMegakernelFrontierExecutionPlanError::GroupOverBudget {
                required_bytes: wave_bytes,
                budget_bytes: group_budget_bytes,
                field: "single fused frontier wave bytes",
            });
        }
        if !current.is_empty() && combined > group_budget_bytes {
            groups.push(CudaMegakernelBarrierGroup {
                waves: std::mem::take(&mut current),
            });
            current_bytes = 0;
        }
        current.push(wave_index);
        current_bytes = checked_add(
            current_bytes,
            wave_bytes,
            "barrier group fused wave budget bytes",
        )?;
    }
    if !current.is_empty() {
        groups.push(CudaMegakernelBarrierGroup { waves: current });
    }
    Ok(())
}

fn reserve_frontier_vec<T>(
    vec: &mut Vec<T>,
    capacity: usize,
    field: &'static str,
) -> Result<(), CudaMegakernelFrontierExecutionPlanError> {
    let additional = if vec.capacity() >= capacity {
        0
    } else {
        capacity - vec.capacity()
    };
    vec.try_reserve_exact(additional).map_err(|error| {
        CudaMegakernelFrontierExecutionPlanError::StorageReserveFailed {
            field,
            requested: capacity,
            message: error.to_string(),
        }
    })
}

fn fused_wave_budget_bytes(
    wave: CudaMegakernelFrontierWave,
) -> Result<u64, CudaMegakernelFrontierExecutionPlanError> {
    let fused_scratch_bytes = checked_mul(wave.scratch_bytes, 4, "fused wave scratch bytes")?;
    let bytes = checked_add(wave.frontier_bytes, fused_scratch_bytes, "fused wave bytes")?;
    checked_add(bytes, wave.output_bytes, "fused wave bytes")
}

#[cfg(test)]
mod tests {
    use super::{
        plan_cuda_frontier_megakernel_execution,
        plan_cuda_frontier_megakernel_execution_with_scratch, plan_cuda_megakernel_barriers,
        plan_cuda_megakernel_barriers_with_scratch, CudaMegakernelBarrierPlanError,
        CudaMegakernelBarrierScratch, CudaMegakernelFrontierExecutionPlanError,
        CudaMegakernelFrontierWave, CudaMegakernelWaveDependency,
    };
    use crate::megakernel_plan_cache::{
        CudaMegakernelAnalysisKind, CudaMegakernelDeviceKey, CudaMegakernelPlanCache,
    };
    use crate::megakernel_scheduler::{
        CudaMegakernelGraphShape, CudaMegakernelScheduleSample, CudaMegakernelTopology,
    };

    #[test]
    fn independent_waves_share_one_barrier_free_group() {
        let plan = plan_cuda_megakernel_barriers(4, &[])
            .expect("Fix: independent CUDA megakernel waves should not need barriers.");

        assert_eq!(plan.global_barriers, 0);
        assert_eq!(plan.groups.len(), 1);
        assert_eq!(plan.groups[0].waves, vec![0, 1, 2, 3]);
    }

    #[test]
    fn dependency_chain_requires_one_barrier_between_each_wave() {
        let plan = plan_cuda_megakernel_barriers(
            4,
            &[
                CudaMegakernelWaveDependency {
                    before: 0,
                    after: 1,
                },
                CudaMegakernelWaveDependency {
                    before: 1,
                    after: 2,
                },
                CudaMegakernelWaveDependency {
                    before: 2,
                    after: 3,
                },
            ],
        )
        .expect("Fix: acyclic CUDA megakernel wave chain should be schedulable.");

        assert_eq!(plan.global_barriers, 3);
        assert_eq!(plan.groups[0].waves, vec![0]);
        assert_eq!(plan.groups[1].waves, vec![1]);
        assert_eq!(plan.groups[2].waves, vec![2]);
        assert_eq!(plan.groups[3].waves, vec![3]);
    }

    #[test]
    fn diamond_dependencies_fuse_middle_waves() {
        let plan = plan_cuda_megakernel_barriers(
            4,
            &[
                CudaMegakernelWaveDependency {
                    before: 0,
                    after: 1,
                },
                CudaMegakernelWaveDependency {
                    before: 0,
                    after: 2,
                },
                CudaMegakernelWaveDependency {
                    before: 1,
                    after: 3,
                },
                CudaMegakernelWaveDependency {
                    before: 2,
                    after: 3,
                },
            ],
        )
        .expect("Fix: diamond CUDA megakernel dependencies should preserve middle-wave fusion.");

        assert_eq!(plan.global_barriers, 2);
        assert_eq!(plan.groups[0].waves, vec![0]);
        assert_eq!(plan.groups[1].waves, vec![1, 2]);
        assert_eq!(plan.groups[2].waves, vec![3]);
    }

    #[test]
    fn barrier_planner_uses_csr_adjacency_for_wide_wave_graphs() {
        let dependencies = (1..1_025)
            .map(|after| CudaMegakernelWaveDependency { before: 0, after })
            .collect::<Vec<_>>();
        let plan = plan_cuda_megakernel_barriers(1_025, &dependencies)
            .expect("Fix: wide CUDA megakernel dependency fanout must schedule without per-wave adjacency allocation.");

        assert_eq!(plan.global_barriers, 1);
        assert_eq!(plan.groups[0].waves, vec![0]);
        assert_eq!(plan.groups[1].waves.len(), 1_024);
        let src = include_str!("megakernel_barrier_planner.rs");
        assert!(
            !src.contains(concat!("vec![", "Vec::new(); wave_count]")),
            "Fix: CUDA megakernel barrier planner must use contiguous CSR adjacency instead of allocating one Vec per wave."
        );
        assert!(
            !src.contains(concat!("outgoing_offsets[..wave_count]", ".to_vec()")),
            "Fix: CUDA megakernel barrier planner must reuse the counts buffer as the CSR write cursor instead of allocating an O(wave_count) cursor Vec."
        );
        assert!(
            !src.contains(concat!("Vec", "Deque")),
            "Fix: CUDA megakernel barrier planner should use contiguous current/next ready vectors, not deque queue mechanics, for wide wave layers."
        );
        assert!(
            !src.contains(concat!("saturating", "_add")),
            "Fix: CUDA megakernel barrier dependency accounting is bounded by the validated graph shape and must not hide invariant violations with saturating arithmetic."
        );
        assert!(
            src.contains("field: \"outgoing dependency count\"")
                && src.contains("field: \"incoming dependency count\"")
                && src.contains("field: \"outgoing dependency offsets\"")
                && src.contains("field: \"outgoing target cursor\""),
            "Fix: CUDA megakernel barrier CSR construction must use checked arithmetic for dependency counters, offsets, and cursors."
        );
        assert!(
            src.contains("fn reserve_barrier_vec<T>(")
                && src.contains("fn fill_barrier_vec_zeroed(")
                && src.contains("fn reserve_frontier_vec<T>(")
                && src.contains("try_reserve_exact(additional)")
                && src.contains("StorageReserveFailed"),
            "Fix: CUDA megakernel barrier and frontier group staging must reserve fallibly instead of panicking under scale pressure."
        );
        assert!(
            !src.contains(concat!("Vec::with_capacity", "(wave_count)"))
                && !src.contains(concat!("Vec::with_capacity", "(barriers.groups.len())"))
                && !src.contains(concat!("Vec::with_capacity", "(group.waves.len().min(8))"))
                && !src.contains(concat!(".reserve", "(wave_count)"))
                && !src.contains(concat!("scratch.outgoing_counts", ".resize"))
                && !src.contains(concat!("scratch.indegree", ".resize"))
                && !src.contains(concat!("scratch.outgoing_targets", ".resize")),
            "Fix: CUDA megakernel barrier planner must not use infallible capacity growth in release topology planning."
        );
        assert!(
            !src.contains(concat!(
                "scratch.outgoing_counts[dependency.before]",
                " += 1"
            ))
                && !src.contains(concat!("scratch.indegree[dependency.after]", " += 1"))
                && !src.contains(concat!(
                    "let next = scratch.outgoing_offsets.last().copied().unwrap_or(0)",
                    " + *count"
                )),
            "Fix: CUDA megakernel barrier planning must not use unchecked usize arithmetic for CSR construction."
        );
    }

    #[test]
    fn barrier_planner_reuses_caller_owned_csr_scratch_across_shapes() {
        let mut scratch = CudaMegakernelBarrierScratch::try_with_capacity(1_025, 1_024)
            .expect("wide reusable CUDA megakernel barrier scratch should fit");
        let wide_dependencies = (1..1_025)
            .map(|after| CudaMegakernelWaveDependency { before: 0, after })
            .collect::<Vec<_>>();
        let wide =
            plan_cuda_megakernel_barriers_with_scratch(1_025, &wide_dependencies, &mut scratch)
                .expect("wide CUDA megakernel dependency fanout should plan with reusable scratch");
        let wave_capacity = scratch.wave_capacity();
        let dependency_capacity = scratch.dependency_capacity();

        assert_eq!(wide.groups[1].waves.len(), 1_024);

        let narrow = plan_cuda_megakernel_barriers_with_scratch(
            4,
            &[
                CudaMegakernelWaveDependency {
                    before: 0,
                    after: 1,
                },
                CudaMegakernelWaveDependency {
                    before: 1,
                    after: 2,
                },
                CudaMegakernelWaveDependency {
                    before: 2,
                    after: 3,
                },
            ],
            &mut scratch,
        )
        .expect("narrow CUDA megakernel dependency chain should reuse larger scratch");

        assert_eq!(narrow.global_barriers, 3);
        assert!(scratch.wave_capacity() >= wave_capacity);
        assert!(scratch.dependency_capacity() >= dependency_capacity);
    }

    #[test]
    fn frontier_execution_planner_accepts_reusable_barrier_scratch() {
        let mut cache = CudaMegakernelPlanCache::new();
        let mut scratch = CudaMegakernelBarrierScratch::try_with_capacity(3, 2)
            .expect("frontier reusable CUDA megakernel barrier scratch should fit");
        let waves = [
            CudaMegakernelFrontierWave {
                frontier_bytes: 128,
                scratch_bytes: 64,
                output_bytes: 32,
            },
            CudaMegakernelFrontierWave {
                frontier_bytes: 256,
                scratch_bytes: 128,
                output_bytes: 64,
            },
            CudaMegakernelFrontierWave {
                frontier_bytes: 512,
                scratch_bytes: 256,
                output_bytes: 128,
            },
        ];
        let dependencies = [
            CudaMegakernelWaveDependency {
                before: 0,
                after: 1,
            },
            CudaMegakernelWaveDependency {
                before: 1,
                after: 2,
            },
        ];

        let plan = plan_cuda_frontier_megakernel_execution_with_scratch(
            &mut cache,
            77,
            CudaMegakernelAnalysisKind::Dataflow,
            device(),
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.4,
                readback_bytes: 16,
            },
            CudaMegakernelGraphShape {
                node_count: 256,
                edge_count: 512,
            },
            16,
            8,
            &waves,
            &dependencies,
            1 << 20,
            400.0,
            1.0,
            &mut scratch,
        )
        .expect("frontier megakernel planner should accept caller-owned barrier scratch");

        assert_eq!(plan.barriers.global_barriers, 2);
        assert!(scratch.wave_capacity() >= 3);
        assert!(scratch.dependency_capacity() >= 2);
    }

    #[test]
    fn invalid_or_cyclic_dependencies_fail_loudly() {
        let invalid = plan_cuda_megakernel_barriers(
            2,
            &[CudaMegakernelWaveDependency {
                before: 0,
                after: 2,
            }],
        )
        .expect_err("Fix: invalid CUDA megakernel wave index must fail before planning.");
        assert!(matches!(
            invalid,
            CudaMegakernelBarrierPlanError::InvalidWave { .. }
        ));

        let cycle = plan_cuda_megakernel_barriers(
            2,
            &[
                CudaMegakernelWaveDependency {
                    before: 0,
                    after: 1,
                },
                CudaMegakernelWaveDependency {
                    before: 1,
                    after: 0,
                },
            ],
        )
        .expect_err(
            "Fix: cyclic CUDA megakernel dependencies require explicit fixed-point kernels.",
        );
        assert_eq!(
            cycle,
            CudaMegakernelBarrierPlanError::Cycle {
                unscheduled_waves: 2
            }
        );
    }

    #[test]
    fn frontier_execution_plan_uses_peak_barrier_group_memory() {
        let mut cache = CudaMegakernelPlanCache::new();
        let plan = plan_cuda_frontier_megakernel_execution(
            &mut cache,
            42,
            CudaMegakernelAnalysisKind::Dataflow,
            device(),
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.90,
                readback_bytes: 1 << 20,
            },
            CudaMegakernelGraphShape {
                node_count: 1_000,
                edge_count: 4_000,
            },
            16,
            8,
            &[
                CudaMegakernelFrontierWave {
                    frontier_bytes: 1_024,
                    scratch_bytes: 512,
                    output_bytes: 256,
                },
                CudaMegakernelFrontierWave {
                    frontier_bytes: 2_048,
                    scratch_bytes: 1_024,
                    output_bytes: 512,
                },
                CudaMegakernelFrontierWave {
                    frontier_bytes: 4_096,
                    scratch_bytes: 2_048,
                    output_bytes: 1_024,
                },
                CudaMegakernelFrontierWave {
                    frontier_bytes: 8_192,
                    scratch_bytes: 4_096,
                    output_bytes: 2_048,
                },
            ],
            &[
                CudaMegakernelWaveDependency {
                    before: 0,
                    after: 1,
                },
                CudaMegakernelWaveDependency {
                    before: 0,
                    after: 2,
                },
                CudaMegakernelWaveDependency {
                    before: 1,
                    after: 3,
                },
                CudaMegakernelWaveDependency {
                    before: 2,
                    after: 3,
                },
            ],
            128 * 1024,
            250.0,
            0.95,
        )
        .expect("Fix: frontier-typed CUDA megakernel execution plan should fit the budget.");

        assert_eq!(plan.barriers.global_barriers, 2);
        assert_eq!(plan.barriers.groups[1].waves, vec![1, 2]);
        assert_eq!(plan.peak_frontier_bytes, 8_192);
        assert_eq!(plan.peak_scratch_bytes, 4_096);
        assert_eq!(plan.peak_output_bytes, 2_048);
        assert_eq!(plan.amortized_readback_bytes, 1 << 20);
        assert_eq!(plan.max_group_width, 2);
        assert_eq!(plan.execution.topology, CudaMegakernelTopology::FusedWave);
        assert_eq!(plan.execution.memory.frontier_bytes, 8_192);
    }

    #[test]
    fn frontier_execution_uses_static_group_output_to_trigger_fusion() {
        let mut cache = CudaMegakernelPlanCache::new();
        let plan = plan_cuda_frontier_megakernel_execution(
            &mut cache,
            77,
            CudaMegakernelAnalysisKind::Dataflow,
            device(),
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.50,
                readback_bytes: 0,
            },
            CudaMegakernelGraphShape {
                node_count: 1_000,
                edge_count: 4_000,
            },
            16,
            8,
            &[
                CudaMegakernelFrontierWave {
                    frontier_bytes: 1_024,
                    scratch_bytes: 512,
                    output_bytes: 3_072,
                },
                CudaMegakernelFrontierWave {
                    frontier_bytes: 1_024,
                    scratch_bytes: 512,
                    output_bytes: 3_072,
                },
            ],
            &[],
            128 * 1024,
            250.0,
            0.95,
        )
        .expect("Fix: static output-amortized CUDA frontier plan should fit the budget.");

        assert_eq!(plan.peak_output_bytes, 6_144);
        assert_eq!(plan.amortized_readback_bytes, 6_144);
        assert_eq!(
            plan.execution.topology,
            CudaMegakernelTopology::FusedWave,
            "Fix: high static fused-group output pressure must trigger megakernel fusion even when the previous telemetry interval had no final readback."
        );
    }

    #[test]
    fn frontier_execution_splits_independent_layers_to_fit_fused_memory_budget() {
        let mut cache = CudaMegakernelPlanCache::new();
        let waves = [
            CudaMegakernelFrontierWave {
                frontier_bytes: 10,
                scratch_bytes: 10,
                output_bytes: 10,
            },
            CudaMegakernelFrontierWave {
                frontier_bytes: 10,
                scratch_bytes: 10,
                output_bytes: 10,
            },
            CudaMegakernelFrontierWave {
                frontier_bytes: 10,
                scratch_bytes: 10,
                output_bytes: 10,
            },
        ];
        let plan = plan_cuda_frontier_megakernel_execution(
            &mut cache,
            909,
            CudaMegakernelAnalysisKind::Dataflow,
            device(),
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.50,
                readback_bytes: 4_096,
            },
            CudaMegakernelGraphShape {
                node_count: 1,
                edge_count: 0,
            },
            0,
            0,
            &waves,
            &[],
            100,
            250.0,
            0.95,
        )
        .expect("Fix: independent CUDA frontier waves should split into memory-fit fused chunks instead of failing the release path.");

        assert_eq!(plan.barriers.groups.len(), 3);
        assert_eq!(plan.barriers.global_barriers, 2);
        assert_eq!(plan.max_group_width, 1);
        assert_eq!(plan.peak_frontier_bytes, 10);
        assert_eq!(plan.peak_scratch_bytes, 10);
        assert_eq!(plan.peak_output_bytes, 10);
        assert_eq!(plan.execution.topology, CudaMegakernelTopology::FusedWave);
        assert_eq!(plan.execution.memory.required_bytes, 60);
    }

    #[test]
    fn frontier_execution_rejects_graph_bytes_over_budget_without_zero_budget_default() {
        let mut cache = CudaMegakernelPlanCache::new();
        let error = plan_cuda_frontier_megakernel_execution(
            &mut cache,
            910,
            CudaMegakernelAnalysisKind::Dataflow,
            device(),
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.50,
                readback_bytes: 4_096,
            },
            CudaMegakernelGraphShape {
                node_count: 100,
                edge_count: 100,
            },
            8,
            8,
            &[CudaMegakernelFrontierWave {
                frontier_bytes: 1,
                scratch_bytes: 1,
                output_bytes: 1,
            }],
            &[],
            1_000,
            250.0,
            0.95,
        )
        .expect_err("resident graph bytes above budget must fail before split planning");

        assert_eq!(
            error,
            CudaMegakernelFrontierExecutionPlanError::GroupOverBudget {
                required_bytes: 1_600,
                budget_bytes: 1_000,
                field: "resident graph bytes",
            }
        );
    }

    #[test]
    fn frontier_execution_rejects_single_wave_that_cannot_fit_group_budget() {
        let mut cache = CudaMegakernelPlanCache::new();
        let error = plan_cuda_frontier_megakernel_execution(
            &mut cache,
            911,
            CudaMegakernelAnalysisKind::Dataflow,
            device(),
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.50,
                readback_bytes: 4_096,
            },
            CudaMegakernelGraphShape {
                node_count: 1,
                edge_count: 0,
            },
            0,
            0,
            &[CudaMegakernelFrontierWave {
                frontier_bytes: 100,
                scratch_bytes: 100,
                output_bytes: 100,
            }],
            &[],
            500,
            250.0,
            0.95,
        )
        .expect_err("single fused wave above group budget must fail before topology planning");

        assert_eq!(
            error,
            CudaMegakernelFrontierExecutionPlanError::GroupOverBudget {
                required_bytes: 600,
                budget_bytes: 500,
                field: "single fused frontier wave bytes",
            }
        );
    }

    #[test]
    fn frontier_execution_plan_reuses_cached_topology_for_equivalent_pressure() {
        let mut cache = CudaMegakernelPlanCache::new();
        let waves = [
            CudaMegakernelFrontierWave {
                frontier_bytes: 1_024,
                scratch_bytes: 512,
                output_bytes: 256,
            },
            CudaMegakernelFrontierWave {
                frontier_bytes: 2_048,
                scratch_bytes: 1_024,
                output_bytes: 512,
            },
        ];
        let first = plan_cuda_frontier_megakernel_execution(
            &mut cache,
            42,
            CudaMegakernelAnalysisKind::ParserFrontend,
            device(),
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.90,
                readback_bytes: 1 << 20,
            },
            CudaMegakernelGraphShape {
                node_count: 1_000,
                edge_count: 4_000,
            },
            16,
            8,
            &waves,
            &[],
            128 * 1024,
            250.0,
            0.95,
        )
        .expect("Fix: first frontier execution plan should fit.");
        let second = plan_cuda_frontier_megakernel_execution(
            &mut cache,
            42,
            CudaMegakernelAnalysisKind::ParserFrontend,
            device(),
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.91,
                readback_bytes: 1 << 20,
            },
            CudaMegakernelGraphShape {
                node_count: 1_000,
                edge_count: 4_000,
            },
            16,
            8,
            &waves,
            &[],
            128 * 1024,
            250.0,
            0.95,
        )
        .expect("Fix: equivalent frontier execution pressure should reuse cached topology.");

        assert_eq!(first.execution.topology, CudaMegakernelTopology::FusedWave);
        assert_eq!(second.execution.topology, CudaMegakernelTopology::FusedWave);
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn frontier_execution_plan_fails_loudly_on_wave_byte_overflow() {
        let mut cache = CudaMegakernelPlanCache::new();
        let error = plan_cuda_frontier_megakernel_execution(
            &mut cache,
            42,
            CudaMegakernelAnalysisKind::Dataflow,
            device(),
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.90,
                readback_bytes: 1 << 20,
            },
            CudaMegakernelGraphShape {
                node_count: 1,
                edge_count: 1,
            },
            1,
            1,
            &[
                CudaMegakernelFrontierWave {
                    frontier_bytes: u64::MAX,
                    scratch_bytes: 1,
                    output_bytes: 1,
                },
                CudaMegakernelFrontierWave {
                    frontier_bytes: 1,
                    scratch_bytes: 1,
                    output_bytes: 1,
                },
            ],
            &[],
            u64::MAX,
            250.0,
            0.95,
        )
        .expect_err("Fix: overflowed frontier wave bytes must fail before CUDA launch planning.");

        assert_eq!(
            error,
            CudaMegakernelFrontierExecutionPlanError::ByteCountOverflow {
                field: "fused wave bytes"
            }
        );
    }

    fn device() -> CudaMegakernelDeviceKey {
        CudaMegakernelDeviceKey {
            sm_major: 12,
            sm_minor: 0,
            warp_size: 32,
            supports_grid_sync: true,
            supports_tensor_cores: true,
            max_workgroup_size: 1024,
        }
    }
}
