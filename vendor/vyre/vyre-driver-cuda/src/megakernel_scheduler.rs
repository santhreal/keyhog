//! CUDA telemetry adapter for the scale-aware megakernel scheduler.

use vyre_self_substrate::megakernel_schedule::{
    try_schedule_via_scale_aware_samples_into, MegakernelScaleSample, MegakernelScheduleError,
};

use crate::backend::CudaTelemetrySnapshot;

const CUDA_WARP_SPARSE_DENSITY: f64 = 0.03125;
const CUDA_SPARSE_DENSITY: f64 = 0.125;
const CUDA_DENSE_DENSITY: f64 = 0.70;
const CUDA_BLOCK_DENSE_DENSITY: f64 = 0.85;
const CUDA_FUSION_PRESSURE: f64 = 0.70;
const CUDA_FUSION_PRESSURE_HYSTERESIS: f64 = 0.10;
const CUDA_FRONTIER_HYSTERESIS: f64 = 0.025;
const CUDA_MEMORY_RED_ZONE_BPS: u32 = 9_000;
const CUDA_MEMORY_HYSTERESIS_BPS: u32 = 250;
const CUDA_LAUNCH_PRESSURE_BPS: u32 = 1_500;
const CUDA_LAUNCH_HYSTERESIS_BPS: u32 = 250;
const CUDA_FUSION_READBACK_BYTES: u64 = 4_096;
const CUDA_DENSE_AVERAGE_DEGREE_BPS: u64 = 20_000;
const CUDA_WARP_SPARSE_AVERAGE_DEGREE_BPS: u64 = 80_000;

/// Per-candidate CUDA telemetry used to bias megakernel fusion.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CudaMegakernelScheduleSample {
    /// Observed candidate dispatch cost in nanoseconds.
    pub dispatch_cost_ns: f64,
    /// Observed active-frontier density in `[0, 1]`.
    pub frontier_density: f64,
    /// Observed final readback byte volume.
    pub readback_bytes: u64,
}

/// Device-side megakernel execution topology selected for a dataflow wave.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CudaMegakernelTopology {
    /// Ultra-low-density frontier expansion where one warp owns sparse active
    /// nodes and avoids block-wide work distribution overhead.
    WarpSparseFrontier,
    /// Low-density frontier expansion with queue-like work distribution.
    SparseFrontier,
    /// Very high-density propagation where a block owns coalesced bitset lanes
    /// and amortizes shared-memory scans across many active facts.
    BlockDenseFrontier,
    /// Dense bitset-style propagation with coalesced scans.
    DenseFrontier,
    /// Mixed sparse/dense execution when density is in the transition band.
    HybridFrontier,
    /// Fused adjacent waves when launch/readback pressure dominates and memory
    /// budget leaves room for the fused plan.
    FusedWave,
}

/// Static graph shape used by CUDA topology selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaMegakernelGraphShape {
    /// Logical graph node count.
    pub node_count: u64,
    /// Logical graph edge count.
    pub edge_count: u64,
}

/// Device memory envelope for a candidate CUDA megakernel plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaMegakernelMemoryBudget {
    /// Estimated resident plus transient bytes required by the candidate plan.
    pub required_bytes: u64,
    /// Caller-approved device-memory budget for the plan.
    pub budget_bytes: u64,
}

/// Detailed CUDA megakernel memory plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaMegakernelMemoryPlan {
    /// Graph-layout bytes retained on device.
    pub graph_bytes: u64,
    /// Frontier-state bytes retained on device.
    pub frontier_bytes: u64,
    /// Temporary scratch bytes required by the selected topology.
    pub scratch_bytes: u64,
    /// Final compact output/readback bytes.
    pub output_bytes: u64,
    /// Total peak bytes required by the plan.
    pub required_bytes: u64,
    /// Caller-approved byte budget.
    pub budget_bytes: u64,
    /// Required/budget pressure in basis points.
    pub memory_pressure_bps: u32,
}

/// Complete CUDA megakernel execution plan selected from runtime telemetry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaMegakernelExecutionPlan {
    /// Final topology after memory-budget validation.
    pub topology: CudaMegakernelTopology,
    /// Memory plan for the final topology.
    pub memory: CudaMegakernelMemoryPlan,
    /// Whether the planner downgraded a denser/fused topology to sparse to fit
    /// the explicit memory budget.
    pub downgraded_to_sparse: bool,
}

/// Memory planning failure for CUDA megakernel execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CudaMegakernelMemoryError {
    /// A byte-count multiplication or addition overflowed.
    ByteCountOverflow {
        /// Field being computed when overflow happened.
        field: &'static str,
    },
    /// The candidate plan exceeds the caller-approved device-memory budget.
    OverBudget {
        /// Selected topology.
        topology: CudaMegakernelTopology,
        /// Required peak bytes.
        required_bytes: u64,
        /// Caller-approved budget bytes.
        budget_bytes: u64,
        /// Graph node count.
        node_count: u64,
        /// Graph edge count.
        edge_count: u64,
    },
}

impl std::fmt::Display for CudaMegakernelMemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ByteCountOverflow { field } => write!(
                f,
                "CUDA megakernel memory planner overflowed while computing {field}. Fix: shard the graph or lower the candidate topology before planning device residency."
            ),
            Self::OverBudget {
                topology,
                required_bytes,
                budget_bytes,
                node_count,
                edge_count,
            } => write!(
                f,
                "CUDA megakernel {topology:?} plan requires {required_bytes} bytes but budget allows {budget_bytes} bytes for graph nodes={node_count} edges={edge_count}. Fix: choose a sparse topology, reduce fusion pressure, shard the graph, or raise the explicit device-memory budget."
            ),
        }
    }
}

impl std::error::Error for CudaMegakernelMemoryError {}

/// Topology decision with the pressure metrics that caused it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CudaMegakernelTopologyDecision {
    /// Selected execution topology.
    pub topology: CudaMegakernelTopology,
    /// Required/budget memory pressure in basis points.
    pub memory_pressure_bps: u32,
    /// Edge/node average degree proxy in basis points.
    pub average_degree_bps: u64,
    /// Launch overhead divided by observed dispatch cost in basis points.
    pub launch_pressure_bps: u32,
}

impl CudaMegakernelTopologyDecision {
    /// Stable single-line explanation for release logs and scheduler debugging.
    #[must_use]
    pub fn stable_explanation(&self) -> String {
        format!(
            "cuda-megakernel-topology-v1|topology={:?}|memory_pressure_bps={}|average_degree_bps={}|launch_pressure_bps={}|reason={}",
            self.topology,
            self.memory_pressure_bps,
            self.average_degree_bps,
            self.launch_pressure_bps,
            self.reason_code()
        )
    }

    fn reason_code(&self) -> &'static str {
        match self.topology {
            CudaMegakernelTopology::WarpSparseFrontier => "ultra_sparse_warp_specialized",
            CudaMegakernelTopology::SparseFrontier if self.memory_pressure_bps >= 9_000 => {
                "memory_pressure_sparse_safety"
            }
            CudaMegakernelTopology::SparseFrontier => "low_density_sparse_queue",
            CudaMegakernelTopology::BlockDenseFrontier => "high_density_block_specialized",
            CudaMegakernelTopology::DenseFrontier => "dense_coalesced_frontier",
            CudaMegakernelTopology::HybridFrontier => "transition_band_hybrid",
            CudaMegakernelTopology::FusedWave => "launch_and_readback_pressure_fused",
        }
    }
}

impl CudaMegakernelScheduleSample {
    /// Build one scheduler sample from an observed CUDA telemetry interval.
    ///
    /// `dispatch_cost_ns` is supplied by the caller because wall/device timing
    /// belongs to the benchmark or timed-dispatch boundary. Frontier density is
    /// derived from launched logical elements over scheduled CUDA thread slots,
    /// which is the runtime proxy available for arbitrary resident kernels.
    #[must_use]
    pub fn from_telemetry_snapshot(snapshot: CudaTelemetrySnapshot, dispatch_cost_ns: f64) -> Self {
        let frontier_density = f64::from(snapshot.logical_thread_utilization_bps) / 10_000.0;
        Self {
            dispatch_cost_ns,
            frontier_density,
            readback_bytes: snapshot.readback_bytes,
        }
    }
}

/// Select the CUDA megakernel execution topology for one candidate wave.
///
/// This is intentionally deterministic and allocation-free so it can sit on
/// the dispatch hot path after telemetry sampling. It prefers fused execution
/// only when fusion pressure is high, launch overhead is material, and memory
/// pressure is below the red zone; otherwise it uses density and graph shape to
/// select sparse, dense, or hybrid traversal.
#[must_use]
pub fn select_cuda_megakernel_topology(
    sample: CudaMegakernelScheduleSample,
    graph: CudaMegakernelGraphShape,
    memory: CudaMegakernelMemoryBudget,
    launch_overhead_ns: f64,
    fusion_pressure: f64,
) -> CudaMegakernelTopologyDecision {
    let memory_pressure_bps = pressure_bps(memory.required_bytes, memory.budget_bytes);
    let average_degree_bps = pressure_bps_u64(graph.edge_count, graph.node_count);
    let launch_pressure_bps =
        if sample.dispatch_cost_ns <= 0.0 || !sample.dispatch_cost_ns.is_finite() {
            0
        } else {
            finite_ratio_bps(
                launch_overhead_ns.max(0.0),
                sample.dispatch_cost_ns,
                "launch overhead pressure",
            )
        };
    let density = if sample.frontier_density.is_finite() {
        sample.frontier_density.clamp(0.0, 1.0)
    } else {
        0.0
    };
    let fusion = if fusion_pressure.is_finite() {
        fusion_pressure.clamp(0.0, 1.0)
    } else {
        0.0
    };
    let topology = if memory_pressure_bps >= CUDA_MEMORY_RED_ZONE_BPS {
        CudaMegakernelTopology::SparseFrontier
    } else if fusion >= CUDA_FUSION_PRESSURE
        && launch_pressure_bps >= CUDA_LAUNCH_PRESSURE_BPS
        && sample.readback_bytes >= CUDA_FUSION_READBACK_BYTES
        && memory_pressure_bps
            <= checked_bps_sub(
                CUDA_MEMORY_RED_ZONE_BPS,
                500,
                "fusion memory red-zone margin",
            )
    {
        CudaMegakernelTopology::FusedWave
    } else if density <= CUDA_WARP_SPARSE_DENSITY
        && average_degree_bps <= CUDA_WARP_SPARSE_AVERAGE_DEGREE_BPS
    {
        CudaMegakernelTopology::WarpSparseFrontier
    } else if density <= CUDA_SPARSE_DENSITY {
        CudaMegakernelTopology::SparseFrontier
    } else if density >= CUDA_BLOCK_DENSE_DENSITY
        && average_degree_bps >= CUDA_DENSE_AVERAGE_DEGREE_BPS
    {
        CudaMegakernelTopology::BlockDenseFrontier
    } else if density >= CUDA_DENSE_DENSITY && average_degree_bps >= CUDA_DENSE_AVERAGE_DEGREE_BPS {
        CudaMegakernelTopology::DenseFrontier
    } else {
        CudaMegakernelTopology::HybridFrontier
    };
    CudaMegakernelTopologyDecision {
        topology,
        memory_pressure_bps,
        average_degree_bps,
        launch_pressure_bps,
    }
}

/// Select CUDA megakernel topology with previous-topology hysteresis.
///
/// Resident dataflow graphs should use this selector when the previous topology
/// for the same graph, analysis family, and CUDA device is known. It keeps
/// sparse/dense/fused kernel variants stable inside narrow transition bands so
/// borderline telemetry does not churn PTX variants, plan-cache entries, and
/// device-resident scratch layout.
#[must_use]
pub fn select_cuda_megakernel_topology_stable(
    sample: CudaMegakernelScheduleSample,
    graph: CudaMegakernelGraphShape,
    memory: CudaMegakernelMemoryBudget,
    launch_overhead_ns: f64,
    fusion_pressure: f64,
    previous_topology: CudaMegakernelTopology,
) -> CudaMegakernelTopologyDecision {
    let mut decision =
        select_cuda_megakernel_topology(sample, graph, memory, launch_overhead_ns, fusion_pressure);
    decision.topology =
        stabilize_cuda_topology(decision, sample, fusion_pressure, previous_topology);
    decision
}

fn stabilize_cuda_topology(
    decision: CudaMegakernelTopologyDecision,
    sample: CudaMegakernelScheduleSample,
    fusion_pressure: f64,
    previous_topology: CudaMegakernelTopology,
) -> CudaMegakernelTopology {
    if decision.memory_pressure_bps >= CUDA_MEMORY_RED_ZONE_BPS {
        return decision.topology;
    }
    let density = if sample.frontier_density.is_finite() {
        sample.frontier_density.clamp(0.0, 1.0)
    } else {
        0.0
    };
    let fusion = if fusion_pressure.is_finite() {
        fusion_pressure.clamp(0.0, 1.0)
    } else {
        0.0
    };
    if matches!(
        previous_topology,
        CudaMegakernelTopology::SparseFrontier | CudaMegakernelTopology::WarpSparseFrontier
    ) && decision.memory_pressure_bps
        >= checked_bps_sub(
            CUDA_MEMORY_RED_ZONE_BPS,
            CUDA_MEMORY_HYSTERESIS_BPS,
            "memory hysteresis floor",
        )
    {
        return CudaMegakernelTopology::SparseFrontier;
    }

    match previous_topology {
        CudaMegakernelTopology::WarpSparseFrontier
            if density <= CUDA_WARP_SPARSE_DENSITY + CUDA_FRONTIER_HYSTERESIS
                && decision.average_degree_bps <= CUDA_WARP_SPARSE_AVERAGE_DEGREE_BPS =>
        {
            CudaMegakernelTopology::WarpSparseFrontier
        }
        CudaMegakernelTopology::SparseFrontier
            if density <= CUDA_SPARSE_DENSITY + CUDA_FRONTIER_HYSTERESIS =>
        {
            CudaMegakernelTopology::SparseFrontier
        }
        CudaMegakernelTopology::HybridFrontier
            if decision.topology == CudaMegakernelTopology::SparseFrontier
                && density >= CUDA_SPARSE_DENSITY - CUDA_FRONTIER_HYSTERESIS =>
        {
            CudaMegakernelTopology::HybridFrontier
        }
        CudaMegakernelTopology::HybridFrontier
            if matches!(
                decision.topology,
                CudaMegakernelTopology::DenseFrontier | CudaMegakernelTopology::BlockDenseFrontier
            ) && density <= CUDA_DENSE_DENSITY + CUDA_FRONTIER_HYSTERESIS =>
        {
            CudaMegakernelTopology::HybridFrontier
        }
        CudaMegakernelTopology::DenseFrontier
            if density >= CUDA_DENSE_DENSITY - CUDA_FRONTIER_HYSTERESIS
                && decision.average_degree_bps >= CUDA_DENSE_AVERAGE_DEGREE_BPS =>
        {
            CudaMegakernelTopology::DenseFrontier
        }
        CudaMegakernelTopology::BlockDenseFrontier
            if density >= CUDA_BLOCK_DENSE_DENSITY - CUDA_FRONTIER_HYSTERESIS
                && decision.average_degree_bps >= CUDA_DENSE_AVERAGE_DEGREE_BPS =>
        {
            CudaMegakernelTopology::BlockDenseFrontier
        }
        CudaMegakernelTopology::FusedWave
            if fusion >= CUDA_FUSION_PRESSURE - CUDA_FUSION_PRESSURE_HYSTERESIS
                && decision.launch_pressure_bps
                    >= checked_bps_sub(
                        CUDA_LAUNCH_PRESSURE_BPS,
                        CUDA_LAUNCH_HYSTERESIS_BPS,
                        "launch hysteresis floor",
                    )
                && sample.readback_bytes >= CUDA_FUSION_READBACK_BYTES
                && decision.memory_pressure_bps
                    <= checked_bps_sub(
                        CUDA_MEMORY_RED_ZONE_BPS,
                        CUDA_MEMORY_HYSTERESIS_BPS,
                        "memory hysteresis floor",
                    ) =>
        {
            CudaMegakernelTopology::FusedWave
        }
        _ => decision.topology,
    }
}

/// Compute and validate a CUDA megakernel device-memory plan.
///
/// The planner is deliberately topology-aware but kernel-agnostic: callers
/// provide stable graph shape plus per-node/per-edge layout widths and the
/// caller-owned frontier/scratch/output envelopes. The result is a bounded
/// peak-memory estimate that fails loudly instead of silently selecting a plan
/// that will OOM during resident upload or fused execution.
pub fn plan_cuda_megakernel_memory_budget(
    topology: CudaMegakernelTopology,
    graph: CudaMegakernelGraphShape,
    bytes_per_node: u64,
    bytes_per_edge: u64,
    frontier_bytes: u64,
    scratch_bytes: u64,
    output_bytes: u64,
    budget_bytes: u64,
) -> Result<CudaMegakernelMemoryPlan, CudaMegakernelMemoryError> {
    let node_bytes = checked_mul(graph.node_count, bytes_per_node, "node layout bytes")?;
    let edge_bytes = checked_mul(graph.edge_count, bytes_per_edge, "edge layout bytes")?;
    let graph_bytes = checked_add(node_bytes, edge_bytes, "graph layout bytes")?;
    let topology_scratch_bytes = topology_scratch_bytes(topology, scratch_bytes)?;
    let required_without_output =
        checked_add(graph_bytes, frontier_bytes, "graph plus frontier bytes")?;
    let required_without_output = checked_add(
        required_without_output,
        topology_scratch_bytes,
        "scratch bytes",
    )?;
    let required_bytes = checked_add(required_without_output, output_bytes, "output bytes")?;
    if required_bytes > budget_bytes {
        return Err(CudaMegakernelMemoryError::OverBudget {
            topology,
            required_bytes,
            budget_bytes,
            node_count: graph.node_count,
            edge_count: graph.edge_count,
        });
    }
    Ok(CudaMegakernelMemoryPlan {
        graph_bytes,
        frontier_bytes,
        scratch_bytes: topology_scratch_bytes,
        output_bytes,
        required_bytes,
        budget_bytes,
        memory_pressure_bps: pressure_bps(required_bytes, budget_bytes),
    })
}

/// Select a CUDA megakernel topology and validate its device-memory plan.
///
/// The function uses sparse-topology bytes as the first-pass pressure estimate
/// for topology choice. If the chosen dense/hybrid/fused topology exceeds the
/// budget, it retries as sparse before returning an over-budget error. This
/// gives the release path one explicit bounded planning boundary instead of
/// scattering "try fused, maybe OOM" decisions across call sites.
pub fn plan_cuda_megakernel_execution(
    sample: CudaMegakernelScheduleSample,
    graph: CudaMegakernelGraphShape,
    bytes_per_node: u64,
    bytes_per_edge: u64,
    frontier_bytes: u64,
    scratch_bytes: u64,
    output_bytes: u64,
    budget_bytes: u64,
    launch_overhead_ns: f64,
    fusion_pressure: f64,
) -> Result<CudaMegakernelExecutionPlan, CudaMegakernelMemoryError> {
    let sparse_memory = plan_cuda_megakernel_memory_budget(
        CudaMegakernelTopology::SparseFrontier,
        graph,
        bytes_per_node,
        bytes_per_edge,
        frontier_bytes,
        scratch_bytes,
        output_bytes,
        budget_bytes,
    )?;
    let decision = select_cuda_megakernel_topology(
        sample,
        graph,
        CudaMegakernelMemoryBudget {
            required_bytes: sparse_memory.required_bytes,
            budget_bytes,
        },
        launch_overhead_ns,
        fusion_pressure,
    );
    match plan_cuda_megakernel_memory_budget(
        decision.topology,
        graph,
        bytes_per_node,
        bytes_per_edge,
        frontier_bytes,
        scratch_bytes,
        output_bytes,
        budget_bytes,
    ) {
        Ok(memory) => Ok(CudaMegakernelExecutionPlan {
            topology: decision.topology,
            memory,
            downgraded_to_sparse: false,
        }),
        Err(CudaMegakernelMemoryError::OverBudget { .. })
            if decision.topology != CudaMegakernelTopology::SparseFrontier =>
        {
            Ok(CudaMegakernelExecutionPlan {
                topology: CudaMegakernelTopology::SparseFrontier,
                memory: sparse_memory,
                downgraded_to_sparse: true,
            })
        }
        Err(error) => Err(error),
    }
}

impl MegakernelScaleSample for CudaMegakernelScheduleSample {
    fn dispatch_cost_ns(&self) -> f64 {
        self.dispatch_cost_ns
    }

    fn frontier_density(&self) -> f64 {
        self.frontier_density
    }

    fn readback_bytes(&self) -> u64 {
        self.readback_bytes
    }
}

/// Schedule megakernel fusion pressure from CUDA telemetry samples.
pub fn schedule_megakernel_from_cuda_samples(
    samples: &[CudaMegakernelScheduleSample],
    launch_overhead_ns: f64,
    n_steps: u32,
    dt: f64,
) -> Result<Vec<f64>, MegakernelScheduleError> {
    let mut out = Vec::new();
    schedule_megakernel_from_cuda_samples_into(samples, launch_overhead_ns, n_steps, dt, &mut out)?;
    Ok(out)
}

/// Schedule megakernel fusion pressure into caller-owned output storage.
pub fn schedule_megakernel_from_cuda_samples_into(
    samples: &[CudaMegakernelScheduleSample],
    launch_overhead_ns: f64,
    n_steps: u32,
    dt: f64,
    out: &mut Vec<f64>,
) -> Result<(), MegakernelScheduleError> {
    try_schedule_via_scale_aware_samples_into(samples, launch_overhead_ns, n_steps, dt, out)
}

fn pressure_bps(numerator: u64, denominator: u64) -> u32 {
    pressure_bps_u64(numerator, denominator).min(10_000) as u32
}

fn pressure_bps_u64(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return if numerator == 0 { 0 } else { u64::MAX };
    }
    let bps = (u128::from(numerator) * 10_000) / u128::from(denominator);
    if bps > u128::from(u64::MAX) {
        tracing::error!(
            "CUDA megakernel pressure bps cannot fit u64. Fix: reduce the scheduling telemetry window."
        );
        return u64::MAX;
    }
    bps as u64
}

fn finite_ratio_bps(numerator: f64, denominator: f64, label: &'static str) -> u32 {
    if !numerator.is_finite() || !denominator.is_finite() || denominator <= 0.0 {
        tracing::error!(
            "CUDA megakernel {label} received non-finite or non-positive timing input. Fix: record finite dispatch timing before topology selection."
        );
        return u32::MAX;
    }
    let bps = (numerator / denominator) * 10_000.0;
    if bps < 0.0 {
        tracing::error!(
            "CUDA megakernel {label} produced negative {bps} bps. Fix: split the schedule sample before policy selection."
        );
        return 0;
    }
    if bps > f64::from(u32::MAX) {
        tracing::error!(
            "CUDA megakernel {label} produced {bps} bps outside u32 range. Fix: split the schedule sample before policy selection."
        );
        return u32::MAX;
    }
    rounded_bps_to_u32(bps, label)
}

fn rounded_bps_to_u32(value: f64, label: &'static str) -> u32 {
    let rounded = value.round();
    if !rounded.is_finite() {
        tracing::error!(
            "CUDA megakernel {label} rounded bps {rounded} is not finite. Fix: keep pressure values in basis-point range."
        );
        return u32::MAX;
    }
    if rounded < 0.0 {
        tracing::error!(
            "CUDA megakernel {label} rounded bps {rounded} is negative. Fix: keep pressure values in basis-point range."
        );
        return 0;
    }
    if rounded > f64::from(u32::MAX) {
        tracing::error!(
            "CUDA megakernel {label} rounded bps {rounded} cannot fit u32. Fix: keep pressure values in basis-point range."
        );
        return u32::MAX;
    }
    rounded as u32
}

fn checked_bps_sub(value: u32, margin: u32, label: &'static str) -> u32 {
    if let Some(result) = value.checked_sub(margin) {
        return result;
    }
    tracing::error!(
        "CUDA megakernel {label} underflowed basis-point threshold. Fix: configure hysteresis below the threshold."
    );
    0
}

fn topology_scratch_bytes(
    topology: CudaMegakernelTopology,
    base_scratch_bytes: u64,
) -> Result<u64, CudaMegakernelMemoryError> {
    match topology {
        CudaMegakernelTopology::WarpSparseFrontier => Ok(base_scratch_bytes.max(32)),
        CudaMegakernelTopology::SparseFrontier => Ok(base_scratch_bytes),
        CudaMegakernelTopology::BlockDenseFrontier => checked_mul(
            base_scratch_bytes.max(1024),
            2,
            "block dense topology scratch bytes",
        ),
        CudaMegakernelTopology::DenseFrontier => {
            checked_mul(base_scratch_bytes, 2, "dense topology scratch bytes")
        }
        CudaMegakernelTopology::HybridFrontier => {
            checked_mul(base_scratch_bytes, 3, "hybrid topology scratch bytes")
        }
        CudaMegakernelTopology::FusedWave => {
            checked_mul(base_scratch_bytes, 4, "fused topology scratch bytes")
        }
    }
}

fn checked_mul(lhs: u64, rhs: u64, field: &'static str) -> Result<u64, CudaMegakernelMemoryError> {
    lhs.checked_mul(rhs)
        .ok_or(CudaMegakernelMemoryError::ByteCountOverflow { field })
}

fn checked_add(lhs: u64, rhs: u64, field: &'static str) -> Result<u64, CudaMegakernelMemoryError> {
    lhs.checked_add(rhs)
        .ok_or(CudaMegakernelMemoryError::ByteCountOverflow { field })
}

#[cfg(test)]
mod tests {
    use super::{
        plan_cuda_megakernel_execution, plan_cuda_megakernel_memory_budget,
        schedule_megakernel_from_cuda_samples_into, select_cuda_megakernel_topology,
        select_cuda_megakernel_topology_stable, CudaMegakernelGraphShape,
        CudaMegakernelMemoryBudget, CudaMegakernelMemoryError, CudaMegakernelScheduleSample,
        CudaMegakernelTopology,
    };
    use crate::backend::CudaTelemetrySnapshot;
    use vyre_self_substrate::megakernel_schedule::MegakernelScheduleError;

    #[test]
    fn cuda_sample_adapter_reuses_output_capacity() {
        let samples = [
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 10.0,
                frontier_density: 0.0,
                readback_bytes: 0,
            },
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 20.0,
                frontier_density: 1.0,
                readback_bytes: 4096,
            },
        ];
        let mut out = Vec::with_capacity(4);
        let ptr = out.as_ptr();
        schedule_megakernel_from_cuda_samples_into(&samples, 5.0, 8, 0.25, &mut out)
            .expect("valid CUDA scheduler samples must schedule");
        assert_eq!(out.len(), 2);
        assert_eq!(out.as_ptr(), ptr);
        assert!(out[1] > out[0]);
    }

    #[test]
    fn cuda_sample_adapter_uses_runtime_telemetry_without_parallel_staging() {
        let sample = CudaMegakernelScheduleSample::from_telemetry_snapshot(
            CudaTelemetrySnapshot {
                readback_bytes: 4096,
                logical_thread_utilization_bps: 3750,
                ..CudaTelemetrySnapshot::default()
            },
            123.0,
        );

        assert_eq!(
            sample,
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 123.0,
                frontier_density: 0.375,
                readback_bytes: 4096,
            }
        );
    }

    #[test]
    fn topology_selector_prefers_sparse_for_low_density_or_memory_pressure() {
        let sample = CudaMegakernelScheduleSample {
            dispatch_cost_ns: 1_000.0,
            frontier_density: 0.01,
            readback_bytes: 1024,
        };
        let graph = CudaMegakernelGraphShape {
            node_count: 1_000,
            edge_count: 10_000,
        };
        let low_density = select_cuda_megakernel_topology(
            sample,
            graph,
            CudaMegakernelMemoryBudget {
                required_bytes: 1_000,
                budget_bytes: 10_000,
            },
            100.0,
            0.0,
        );
        assert_eq!(low_density.topology, CudaMegakernelTopology::SparseFrontier);

        let memory_red_zone = select_cuda_megakernel_topology(
            CudaMegakernelScheduleSample {
                frontier_density: 0.95,
                readback_bytes: 1 << 20,
                ..sample
            },
            graph,
            CudaMegakernelMemoryBudget {
                required_bytes: 95,
                budget_bytes: 100,
            },
            500.0,
            1.0,
        );
        assert_eq!(
            memory_red_zone.topology,
            CudaMegakernelTopology::SparseFrontier
        );
        assert_eq!(memory_red_zone.memory_pressure_bps, 9_500);
    }

    #[test]
    fn topology_selector_uses_warp_sparse_for_ultra_low_density() {
        let decision = select_cuda_megakernel_topology(
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.01,
                readback_bytes: 256,
            },
            CudaMegakernelGraphShape {
                node_count: 1_000,
                edge_count: 4_000,
            },
            CudaMegakernelMemoryBudget {
                required_bytes: 1_000,
                budget_bytes: 10_000,
            },
            100.0,
            0.0,
        );

        assert_eq!(
            decision.topology,
            CudaMegakernelTopology::WarpSparseFrontier
        );
        assert_eq!(decision.average_degree_bps, 40_000);
        assert_eq!(
            decision.stable_explanation(),
            "cuda-megakernel-topology-v1|topology=WarpSparseFrontier|memory_pressure_bps=1000|average_degree_bps=40000|launch_pressure_bps=1000|reason=ultra_sparse_warp_specialized"
        );
    }

    #[test]
    fn topology_selector_uses_dense_hybrid_and_fused_bands() {
        let graph = CudaMegakernelGraphShape {
            node_count: 1_000,
            edge_count: 4_000,
        };
        let memory = CudaMegakernelMemoryBudget {
            required_bytes: 1_000,
            budget_bytes: 10_000,
        };
        let block_dense = select_cuda_megakernel_topology(
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.90,
                readback_bytes: 512,
            },
            graph,
            memory,
            100.0,
            0.0,
        );
        assert_eq!(
            block_dense.topology,
            CudaMegakernelTopology::BlockDenseFrontier
        );

        let dense = select_cuda_megakernel_topology(
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.75,
                readback_bytes: 512,
            },
            graph,
            memory,
            100.0,
            0.0,
        );
        assert_eq!(dense.topology, CudaMegakernelTopology::DenseFrontier);

        let hybrid = select_cuda_megakernel_topology(
            CudaMegakernelScheduleSample {
                frontier_density: 0.35,
                ..CudaMegakernelScheduleSample {
                    dispatch_cost_ns: 1_000.0,
                    frontier_density: 0.0,
                    readback_bytes: 512,
                }
            },
            graph,
            memory,
            100.0,
            0.0,
        );
        assert_eq!(hybrid.topology, CudaMegakernelTopology::HybridFrontier);

        let fused = select_cuda_megakernel_topology(
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.50,
                readback_bytes: 1 << 20,
            },
            graph,
            memory,
            250.0,
            0.90,
        );
        assert_eq!(fused.topology, CudaMegakernelTopology::FusedWave);
        assert_eq!(fused.launch_pressure_bps, 2_500);
    }

    #[test]
    fn stable_topology_selector_prevents_cuda_variant_flapping_near_thresholds() {
        let graph = CudaMegakernelGraphShape {
            node_count: 1_000,
            edge_count: 4_000,
        };
        let memory = CudaMegakernelMemoryBudget {
            required_bytes: 1_000,
            budget_bytes: 10_000,
        };
        let sparse_to_hybrid = select_cuda_megakernel_topology_stable(
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.14,
                readback_bytes: 512,
            },
            graph,
            memory,
            100.0,
            0.0,
            CudaMegakernelTopology::SparseFrontier,
        );
        assert_eq!(
            sparse_to_hybrid.topology,
            CudaMegakernelTopology::SparseFrontier
        );

        let dense_to_hybrid = select_cuda_megakernel_topology_stable(
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.68,
                readback_bytes: 512,
            },
            graph,
            memory,
            100.0,
            0.0,
            CudaMegakernelTopology::DenseFrontier,
        );
        assert_eq!(
            dense_to_hybrid.topology,
            CudaMegakernelTopology::DenseFrontier
        );

        let fused_to_hybrid = select_cuda_megakernel_topology_stable(
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.50,
                readback_bytes: 1 << 20,
            },
            graph,
            memory,
            130.0,
            0.65,
            CudaMegakernelTopology::FusedWave,
        );
        assert_eq!(fused_to_hybrid.topology, CudaMegakernelTopology::FusedWave);
    }

    #[test]
    fn memory_planner_bounds_peak_bytes_by_topology() {
        let graph = CudaMegakernelGraphShape {
            node_count: 1_000,
            edge_count: 4_000,
        };
        let plan = plan_cuda_megakernel_memory_budget(
            CudaMegakernelTopology::FusedWave,
            graph,
            16,
            8,
            4_096,
            2_048,
            512,
            128 * 1024,
        )
        .expect("valid fused plan should fit the explicit device-memory budget");

        assert_eq!(plan.graph_bytes, 48_000);
        assert_eq!(plan.scratch_bytes, 8_192);
        assert_eq!(plan.required_bytes, 60_800);
        assert!(plan.memory_pressure_bps > 0);
    }

    #[test]
    fn memory_planner_fails_loudly_when_budget_is_exceeded() {
        let graph = CudaMegakernelGraphShape {
            node_count: 1_000,
            edge_count: 4_000,
        };
        let err = plan_cuda_megakernel_memory_budget(
            CudaMegakernelTopology::DenseFrontier,
            graph,
            16,
            8,
            4_096,
            2_048,
            512,
            32 * 1024,
        )
        .expect_err("over-budget dense plan must fail before CUDA allocation");

        assert!(matches!(
            err,
            CudaMegakernelMemoryError::OverBudget {
                topology: CudaMegakernelTopology::DenseFrontier,
                ..
            }
        ));
        assert!(
            err.to_string().contains("Fix: choose a sparse topology"),
            "memory planner errors must be actionable: {err}"
        );
    }

    #[test]
    fn memory_planner_rejects_overflowing_graph_shapes() {
        let err = plan_cuda_megakernel_memory_budget(
            CudaMegakernelTopology::SparseFrontier,
            CudaMegakernelGraphShape {
                node_count: u64::MAX,
                edge_count: 0,
            },
            2,
            0,
            0,
            0,
            0,
            u64::MAX,
        )
        .expect_err("overflowing graph byte count must be rejected");
        assert!(matches!(
            err,
            CudaMegakernelMemoryError::ByteCountOverflow {
                field: "node layout bytes"
            }
        ));
    }

    #[test]
    fn topology_pressure_math_is_exact_for_u64_scale_inputs() {
        let decision = select_cuda_megakernel_topology(
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.95,
                readback_bytes: u64::MAX,
            },
            CudaMegakernelGraphShape {
                node_count: 1_u64 << 60,
                edge_count: 1_u64 << 62,
            },
            CudaMegakernelMemoryBudget {
                required_bytes: 1_u64 << 62,
                budget_bytes: 1_u64 << 63,
            },
            250.0,
            0.0,
        );

        assert_eq!(decision.memory_pressure_bps, 5_000);
        assert_eq!(
            decision.average_degree_bps,
            (((u128::from(1_u64 << 62)) * 10_000) / u128::from(1_u64 << 60)) as u64
        );
    }

    #[test]
    fn execution_planner_selects_fused_when_budget_allows() {
        let plan = plan_cuda_megakernel_execution(
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.50,
                readback_bytes: 1 << 20,
            },
            CudaMegakernelGraphShape {
                node_count: 1_000,
                edge_count: 4_000,
            },
            16,
            8,
            4_096,
            2_048,
            512,
            128 * 1024,
            250.0,
            0.90,
        )
        .expect("fused execution should fit this explicit device-memory budget");

        assert_eq!(plan.topology, CudaMegakernelTopology::FusedWave);
        assert!(!plan.downgraded_to_sparse);
        assert_eq!(plan.memory.scratch_bytes, 8_192);
    }

    #[test]
    fn execution_planner_downgrades_to_sparse_before_over_budget_failure() {
        let plan = plan_cuda_megakernel_execution(
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1_000.0,
                frontier_density: 0.50,
                readback_bytes: 1 << 20,
            },
            CudaMegakernelGraphShape {
                node_count: 1_000,
                edge_count: 4_000,
            },
            16,
            8,
            4_096,
            10_000,
            512,
            80_000,
            250.0,
            0.90,
        )
        .expect("sparse downgrade should fit even when fused topology exceeds the budget");

        assert_eq!(plan.topology, CudaMegakernelTopology::SparseFrontier);
        assert!(plan.downgraded_to_sparse);
        assert_eq!(plan.memory.scratch_bytes, 10_000);
    }

    #[test]
    fn cuda_sample_adapter_does_not_stage_parallel_vectors() {
        let src = include_str!("megakernel_scheduler.rs");
        assert!(
            !src.contains(concat!("let mut costs", " = Vec"))
                && !src.contains(concat!("let mut frontier_density", " = Vec"))
                && !src.contains(concat!("let mut readback_bytes", " = Vec")),
            "CUDA megakernel scheduler must consume native samples directly instead of allocating parallel staging vectors"
        );
    }

    #[test]
    fn cuda_sample_adapter_preserves_scheduler_validation_errors() {
        let samples = [CudaMegakernelScheduleSample {
            dispatch_cost_ns: 10.0,
            frontier_density: 1.5,
            readback_bytes: 0,
        }];
        let err = super::schedule_megakernel_from_cuda_samples(&samples, 0.0, 8, 0.25)
            .expect_err("invalid frontier density must be rejected");
        assert!(matches!(
            err,
            MegakernelScheduleError::InvalidFrontierDensity { index: 0, .. }
        ));
    }
}
