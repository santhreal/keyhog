//! CUDA execution planner for unified token/fact graph frontier waves.

use crate::device_work_queue::{
    plan_cuda_device_work_queue, CudaDeviceWorkQueueError, CudaDeviceWorkQueuePlan,
    CudaDeviceWorkQueueProfile, CudaWorkQueueHostSync,
};
use crate::frontier_typed_ir_adapter::CudaFrontierTypedIrInput;
use crate::megakernel_barrier_planner::{
    plan_cuda_frontier_megakernel_execution_with_scratch, CudaMegakernelBarrierScratch,
    CudaMegakernelFrontierExecutionPlan, CudaMegakernelFrontierExecutionPlanError,
};
use crate::megakernel_plan_cache::{
    CudaMegakernelAnalysisKind, CudaMegakernelDeviceKey, CudaMegakernelPlanCache,
};
use crate::megakernel_scheduler::CudaMegakernelScheduleSample;
use crate::token_fact_graph_cuda_adapter::CudaTokenFactGraphLayout;
use vyre_driver::ResidentGraphReuseTelemetry;

/// Dependency-aware CUDA execution plan for a unified token/fact graph.
#[derive(Clone, Debug, PartialEq)]
pub struct CudaTokenFactFrontierExecutionPlan {
    /// Existing CUDA frontier execution plan.
    pub frontier: CudaMegakernelFrontierExecutionPlan,
    /// Resident device-side work queue for dependent frontier draining.
    pub work_queue: CudaDeviceWorkQueuePlan,
    /// Resident payload bytes subtracted from the scheduler budget.
    pub resident_payload_bytes: u64,
    /// Resident work-queue bytes subtracted from the scheduler budget.
    pub resident_work_queue_bytes: u64,
    /// Total required bytes including graph records, frontier envelopes, and payload slab.
    pub total_required_bytes: u64,
}

/// Whether the token/fact graph must be uploaded for this execution plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CudaTokenFactGraphResidency {
    /// The graph is not resident yet; this plan includes one graph upload.
    ColdUpload,
    /// The graph is already resident on device; this plan reuses it.
    WarmResident,
}

/// CUDA token/fact execution envelope with explicit graph-residency accounting.
#[derive(Clone, Debug, PartialEq)]
pub struct CudaTokenFactFrontierExecutionEnvelope {
    /// Device execution plan.
    pub plan: CudaTokenFactFrontierExecutionPlan,
    /// Backend-neutral cold-upload/warm-reuse graph telemetry.
    pub graph_reuse: ResidentGraphReuseTelemetry,
    /// Resident node+edge graph bytes that must remain live during execution.
    pub resident_graph_bytes: u64,
    /// Graph bytes uploaded by this plan. Zero for warm resident graphs.
    pub graph_upload_bytes: u64,
    /// Graph upload bytes avoided by reusing a warm resident graph.
    pub avoided_graph_upload_bytes: u64,
    /// Total live resident bytes required during execution.
    pub total_resident_bytes: u64,
}

/// Errors from token/fact frontier execution planning.
#[derive(Clone, Debug, PartialEq)]
pub enum CudaTokenFactFrontierExecutionError {
    /// Resident token/fact graph topology cannot be empty on the CUDA release path.
    ZeroResidentGraphBytes,
    /// The public CUDA token/fact layout reported inconsistent resident bytes.
    ResidentGraphByteEnvelopeMismatch {
        /// Node+edge+payload bytes computed from layout fields.
        expected_bytes: u64,
        /// Layout-reported resident byte total.
        actual_bytes: u64,
    },
    /// Payload alone exceeds the explicit device-memory budget.
    PayloadExceedsBudget {
        /// Resident payload bytes.
        payload_bytes: u64,
        /// Caller-provided budget.
        budget_bytes: u64,
    },
    /// Total byte arithmetic overflowed.
    ByteCountOverflow {
        /// Field being computed.
        field: &'static str,
    },
    /// Frontier wave count and active-item count must match exactly.
    ActiveItemWaveCountMismatch {
        /// Number of wave memory envelopes.
        waves: usize,
        /// Number of active-item entries.
        active_items: usize,
    },
    /// Underlying frontier planner rejected the execution plan.
    FrontierPlan(CudaMegakernelFrontierExecutionPlanError),
    /// Device work-queue planning rejected the execution plan.
    WorkQueue(CudaDeviceWorkQueueError),
}

impl std::fmt::Display for CudaTokenFactFrontierExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroResidentGraphBytes => write!(
                f,
                "CUDA token/fact frontier plan received an empty resident graph topology. Fix: build a concrete token/fact graph before CUDA execution planning."
            ),
            Self::ResidentGraphByteEnvelopeMismatch {
                expected_bytes,
                actual_bytes,
            } => write!(
                f,
                "CUDA token/fact frontier layout reports {actual_bytes} resident bytes but node+edge+payload fields require {expected_bytes}. Fix: rebuild the CUDA token/fact layout from the canonical adapter before planning."
            ),
            Self::PayloadExceedsBudget {
                payload_bytes,
                budget_bytes,
            } => write!(
                f,
                "CUDA token/fact frontier plan payload requires {payload_bytes} bytes but budget allows {budget_bytes}. Fix: shard the token/fact payload slab before megakernel planning."
            ),
            Self::ByteCountOverflow { field } => write!(
                f,
                "CUDA token/fact frontier planner overflowed while computing {field}. Fix: shard the resident token/fact graph before CUDA execution planning."
            ),
            Self::ActiveItemWaveCountMismatch {
                waves,
                active_items,
            } => write!(
                f,
                "CUDA token/fact frontier plan has {waves} wave envelope(s) but {active_items} active-item count(s). Fix: preserve one active-item entry per frontier wave before device work-queue planning."
            ),
            Self::FrontierPlan(err) => write!(f, "{err}"),
            Self::WorkQueue(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for CudaTokenFactFrontierExecutionError {}

impl From<CudaMegakernelFrontierExecutionPlanError> for CudaTokenFactFrontierExecutionError {
    fn from(err: CudaMegakernelFrontierExecutionPlanError) -> Self {
        Self::FrontierPlan(err)
    }
}

impl From<CudaDeviceWorkQueueError> for CudaTokenFactFrontierExecutionError {
    fn from(err: CudaDeviceWorkQueueError) -> Self {
        Self::WorkQueue(err)
    }
}

/// Plan dependency-aware CUDA execution for frontier waves over a token/fact graph.
pub fn plan_cuda_token_fact_frontier_execution(
    cache: &mut CudaMegakernelPlanCache,
    graph_layout_hash: u64,
    analysis_kind: CudaMegakernelAnalysisKind,
    device: CudaMegakernelDeviceKey,
    sample: CudaMegakernelScheduleSample,
    graph_layout: CudaTokenFactGraphLayout,
    frontier_input: &CudaFrontierTypedIrInput,
    budget_bytes: u64,
    launch_overhead_ns: f64,
    fusion_pressure: f64,
) -> Result<CudaTokenFactFrontierExecutionPlan, CudaTokenFactFrontierExecutionError> {
    let mut barrier_scratch = CudaMegakernelBarrierScratch::try_with_capacity(
        frontier_input.waves.len(),
        frontier_input.dependencies.len(),
    )
    .map_err(CudaMegakernelFrontierExecutionPlanError::Barrier)?;
    plan_cuda_token_fact_frontier_execution_with_scratch(
        cache,
        graph_layout_hash,
        analysis_kind,
        device,
        sample,
        graph_layout,
        frontier_input,
        budget_bytes,
        launch_overhead_ns,
        fusion_pressure,
        &mut barrier_scratch,
    )
}

/// Plan dependency-aware CUDA execution and expose explicit graph-residency
/// accounting.
pub fn plan_cuda_token_fact_frontier_execution_envelope(
    cache: &mut CudaMegakernelPlanCache,
    graph_layout_hash: u64,
    analysis_kind: CudaMegakernelAnalysisKind,
    device: CudaMegakernelDeviceKey,
    sample: CudaMegakernelScheduleSample,
    graph_layout: CudaTokenFactGraphLayout,
    graph_residency: CudaTokenFactGraphResidency,
    frontier_input: &CudaFrontierTypedIrInput,
    budget_bytes: u64,
    launch_overhead_ns: f64,
    fusion_pressure: f64,
) -> Result<CudaTokenFactFrontierExecutionEnvelope, CudaTokenFactFrontierExecutionError> {
    let mut barrier_scratch = CudaMegakernelBarrierScratch::try_with_capacity(
        frontier_input.waves.len(),
        frontier_input.dependencies.len(),
    )
    .map_err(CudaMegakernelFrontierExecutionPlanError::Barrier)?;
    plan_cuda_token_fact_frontier_execution_envelope_with_scratch(
        cache,
        graph_layout_hash,
        analysis_kind,
        device,
        sample,
        graph_layout,
        graph_residency,
        frontier_input,
        budget_bytes,
        launch_overhead_ns,
        fusion_pressure,
        &mut barrier_scratch,
    )
}

/// Plan dependency-aware CUDA execution using caller-owned megakernel barrier scratch.
pub fn plan_cuda_token_fact_frontier_execution_with_scratch(
    cache: &mut CudaMegakernelPlanCache,
    graph_layout_hash: u64,
    analysis_kind: CudaMegakernelAnalysisKind,
    device: CudaMegakernelDeviceKey,
    sample: CudaMegakernelScheduleSample,
    graph_layout: CudaTokenFactGraphLayout,
    frontier_input: &CudaFrontierTypedIrInput,
    budget_bytes: u64,
    launch_overhead_ns: f64,
    fusion_pressure: f64,
    barrier_scratch: &mut CudaMegakernelBarrierScratch,
) -> Result<CudaTokenFactFrontierExecutionPlan, CudaTokenFactFrontierExecutionError> {
    Ok(
        plan_cuda_token_fact_frontier_execution_envelope_with_scratch(
            cache,
            graph_layout_hash,
            analysis_kind,
            device,
            sample,
            graph_layout,
            CudaTokenFactGraphResidency::ColdUpload,
            frontier_input,
            budget_bytes,
            launch_overhead_ns,
            fusion_pressure,
            barrier_scratch,
        )?
        .plan,
    )
}

/// Plan dependency-aware CUDA execution with explicit graph-residency
/// accounting.
pub fn plan_cuda_token_fact_frontier_execution_envelope_with_scratch(
    cache: &mut CudaMegakernelPlanCache,
    graph_layout_hash: u64,
    analysis_kind: CudaMegakernelAnalysisKind,
    device: CudaMegakernelDeviceKey,
    sample: CudaMegakernelScheduleSample,
    graph_layout: CudaTokenFactGraphLayout,
    graph_residency: CudaTokenFactGraphResidency,
    frontier_input: &CudaFrontierTypedIrInput,
    budget_bytes: u64,
    launch_overhead_ns: f64,
    fusion_pressure: f64,
    barrier_scratch: &mut CudaMegakernelBarrierScratch,
) -> Result<CudaTokenFactFrontierExecutionEnvelope, CudaTokenFactFrontierExecutionError> {
    if frontier_input.active_items.len() != frontier_input.waves.len() {
        return Err(
            CudaTokenFactFrontierExecutionError::ActiveItemWaveCountMismatch {
                waves: frontier_input.waves.len(),
                active_items: frontier_input.active_items.len(),
            },
        );
    }
    let resident_graph_bytes = graph_layout
        .node_bytes
        .checked_add(graph_layout.edge_bytes)
        .ok_or(CudaTokenFactFrontierExecutionError::ByteCountOverflow {
            field: "resident token/fact graph bytes",
        })?;
    if resident_graph_bytes == 0 {
        return Err(CudaTokenFactFrontierExecutionError::ZeroResidentGraphBytes);
    }
    let expected_resident_bytes = resident_graph_bytes
        .checked_add(graph_layout.payload_bytes)
        .ok_or(CudaTokenFactFrontierExecutionError::ByteCountOverflow {
            field: "resident token/fact graph envelope bytes",
        })?;
    if expected_resident_bytes != graph_layout.resident_bytes {
        return Err(
            CudaTokenFactFrontierExecutionError::ResidentGraphByteEnvelopeMismatch {
                expected_bytes: expected_resident_bytes,
                actual_bytes: graph_layout.resident_bytes,
            },
        );
    }
    let payload_budget = budget_bytes.checked_sub(graph_layout.payload_bytes).ok_or(
        CudaTokenFactFrontierExecutionError::PayloadExceedsBudget {
            payload_bytes: graph_layout.payload_bytes,
            budget_bytes,
        },
    )?;
    let active_items = total_active_items(&frontier_input.active_items)?;
    let work_queue = if active_items == 0 {
        empty_device_work_queue_plan()
    } else {
        plan_cuda_device_work_queue(CudaDeviceWorkQueueProfile {
            initial_items: active_items,
            queue_capacity: active_items,
            entry_bytes: 4,
            control_bytes: 16,
            budget_bytes: payload_budget,
            host_sync: CudaWorkQueueHostSync::FinalOnly,
        })?
    };
    let scheduler_budget = payload_budget
        .checked_sub(work_queue.resident_bytes)
        .ok_or(CudaTokenFactFrontierExecutionError::ByteCountOverflow {
            field: "scheduler budget after work queue",
        })?;
    let frontier = plan_cuda_frontier_megakernel_execution_with_scratch(
        cache,
        graph_layout_hash,
        analysis_kind,
        device,
        sample,
        graph_layout.graph_shape,
        graph_layout.node_record_bytes,
        graph_layout.edge_record_bytes,
        &frontier_input.waves,
        &frontier_input.dependencies,
        scheduler_budget,
        launch_overhead_ns,
        fusion_pressure,
        barrier_scratch,
    )?;
    let total_required_bytes = frontier
        .execution
        .memory
        .required_bytes
        .checked_add(graph_layout.payload_bytes)
        .and_then(|bytes| bytes.checked_add(work_queue.resident_bytes))
        .ok_or(CudaTokenFactFrontierExecutionError::ByteCountOverflow {
            field: "total required bytes",
        })?;

    let plan = CudaTokenFactFrontierExecutionPlan {
        frontier,
        work_queue,
        resident_payload_bytes: graph_layout.payload_bytes,
        resident_work_queue_bytes: work_queue.resident_bytes,
        total_required_bytes,
    };
    let graph_upload_bytes = match graph_residency {
        CudaTokenFactGraphResidency::ColdUpload => resident_graph_bytes,
        CudaTokenFactGraphResidency::WarmResident => 0,
    };
    let avoided_graph_upload_bytes = match graph_residency {
        CudaTokenFactGraphResidency::ColdUpload => 0,
        CudaTokenFactGraphResidency::WarmResident => resident_graph_bytes,
    };
    let graph_reuse = match graph_residency {
        CudaTokenFactGraphResidency::ColdUpload => {
            ResidentGraphReuseTelemetry::cold_upload(resident_graph_bytes)
        }
        CudaTokenFactGraphResidency::WarmResident => {
            ResidentGraphReuseTelemetry::warm_reuse(resident_graph_bytes)
        }
    };
    Ok(CudaTokenFactFrontierExecutionEnvelope {
        total_resident_bytes: plan.total_required_bytes,
        plan,
        graph_reuse,
        resident_graph_bytes,
        graph_upload_bytes,
        avoided_graph_upload_bytes,
    })
}

fn total_active_items(active_items: &[u64]) -> Result<u64, CudaTokenFactFrontierExecutionError> {
    let mut total = 0_u64;
    for &items in active_items {
        total = total.checked_add(items).ok_or(
            CudaTokenFactFrontierExecutionError::ByteCountOverflow {
                field: "total active frontier items",
            },
        )?;
    }
    Ok(total)
}

fn empty_device_work_queue_plan() -> CudaDeviceWorkQueuePlan {
    CudaDeviceWorkQueuePlan {
        queue_bytes: 0,
        control_bytes: 0,
        resident_bytes: 0,
        initial_occupancy_bps: 0,
        final_only_host_sync: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontier_typed_ir_adapter::adapt_frontier_typed_ir_to_cuda;
    use crate::token_fact_graph_cuda_adapter::adapt_token_fact_graph_to_cuda_layout;
    use vyre_self_substrate::device_resident_token_fact_graph::{
        plan_device_resident_token_fact_graph, TokenFactEdge, TokenFactEdgeKind, TokenFactNode,
        TokenFactNodeKind,
    };
    use vyre_self_substrate::frontier_typed_ir::{
        plan_frontier_typed_ir, FrontierDependency, FrontierDomain, FrontierNode,
    };

    #[test]
    fn planner_combines_token_fact_residency_with_frontier_barriers() {
        let graph = plan_device_resident_token_fact_graph(
            &[
                node(1, TokenFactNodeKind::Token, 0, 16),
                node(2, TokenFactNodeKind::Semantic, 16, 16),
                node(3, TokenFactNodeKind::Fact, 32, 16),
            ],
            &[
                edge(1, 2, TokenFactEdgeKind::SemanticFact),
                edge(2, 3, TokenFactEdgeKind::FactDependency),
            ],
            48,
        )
        .expect("Fix: token/fact graph should pack");
        let graph_layout = adapt_token_fact_graph_to_cuda_layout(&graph, 32, 16)
            .expect("Fix: token/fact graph should adapt");
        let frontier_plan = plan_frontier_typed_ir(
            &[
                frontier_node(10, FrontierDomain::Parser, 4),
                frontier_node(20, FrontierDomain::Semantic, 4),
                frontier_node(30, FrontierDomain::Dataflow, 4),
            ],
            &[
                FrontierDependency {
                    before: 10,
                    after: 20,
                },
                FrontierDependency {
                    before: 20,
                    after: 30,
                },
            ],
        )
        .expect("Fix: frontier plan should build");
        let frontier_input = adapt_frontier_typed_ir_to_cuda(&frontier_plan, 8, 16, 8)

            .expect("Fix: frontier plan should adapt");
        let mut cache = CudaMegakernelPlanCache::new();

        let plan = plan_cuda_token_fact_frontier_execution(
            &mut cache,
            0xfeed,
            CudaMegakernelAnalysisKind::ParserFrontend,
            device(),
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 100_000.0,
                frontier_density: 0.10,
                readback_bytes: 24,
            },
            graph_layout,
            &frontier_input,
            8_192,
            1_000.0,
            0.0,
        )
        .expect("Fix: token/fact frontier execution should plan");

        assert_eq!(plan.frontier.barriers.global_barriers, 2);
        assert_eq!(plan.work_queue.queue_bytes, 12 * 4);
        assert_eq!(plan.resident_work_queue_bytes, 64);
        assert_eq!(plan.resident_payload_bytes, 48);
        assert!(plan.total_required_bytes >= plan.frontier.execution.memory.required_bytes);
    }

    #[test]
    fn planner_rejects_payload_that_exceeds_budget_before_frontier_planning() {
        let graph = plan_device_resident_token_fact_graph(
            &[node(1, TokenFactNodeKind::Token, 0, 64)],
            &[],
            64,
        )
        .expect("Fix: token/fact graph should pack");
        let graph_layout = adapt_token_fact_graph_to_cuda_layout(&graph, 32, 16)
            .expect("Fix: token/fact graph should adapt");
        let frontier_input = CudaFrontierTypedIrInput {
            waves: Vec::new(),
            active_items: Vec::new(),
            dependencies: Vec::new(),
        };
        let mut cache = CudaMegakernelPlanCache::new();

        assert_eq!(
            plan_cuda_token_fact_frontier_execution(
                &mut cache,
                0xfeed,
                CudaMegakernelAnalysisKind::ParserFrontend,
                device(),
                CudaMegakernelScheduleSample {
                    dispatch_cost_ns: 1.0,
                    frontier_density: 0.0,
                    readback_bytes: 0,
                },
                graph_layout,
                &frontier_input,
                63,
                0.0,
                0.0,
            )
            .expect_err("payload over budget should fail before cache planning"),
            CudaTokenFactFrontierExecutionError::PayloadExceedsBudget {
                payload_bytes: 64,
                budget_bytes: 63,
            }
        );
    }

    #[test]
    fn planner_rejects_invalid_public_token_fact_layout_envelope() {
        let frontier_input = CudaFrontierTypedIrInput {
            waves: Vec::new(),
            active_items: Vec::new(),
            dependencies: Vec::new(),
        };
        let mut cache = CudaMegakernelPlanCache::new();
        let sample = CudaMegakernelScheduleSample {
            dispatch_cost_ns: 1.0,
            frontier_density: 0.0,
            readback_bytes: 0,
        };

        assert_eq!(
            plan_cuda_token_fact_frontier_execution(
                &mut cache,
                0xfeed,
                CudaMegakernelAnalysisKind::ParserFrontend,
                device(),
                sample,
                CudaTokenFactGraphLayout {
                    graph_shape: crate::megakernel_scheduler::CudaMegakernelGraphShape {
                        node_count: 0,
                        edge_count: 0,
                    },
                    node_record_bytes: 32,
                    edge_record_bytes: 16,
                    node_bytes: 0,
                    edge_bytes: 0,
                    payload_bytes: 0,
                    resident_bytes: 0,
                },
                &frontier_input,
                8_192,
                0.0,
                0.0,
            )
            .expect_err("empty resident topology should fail before CUDA planning"),
            CudaTokenFactFrontierExecutionError::ZeroResidentGraphBytes
        );

        assert_eq!(
            plan_cuda_token_fact_frontier_execution(
                &mut cache,
                0xfeed,
                CudaMegakernelAnalysisKind::ParserFrontend,
                device(),
                sample,
                CudaTokenFactGraphLayout {
                    graph_shape: crate::megakernel_scheduler::CudaMegakernelGraphShape {
                        node_count: 1,
                        edge_count: 1,
                    },
                    node_record_bytes: 32,
                    edge_record_bytes: 16,
                    node_bytes: 32,
                    edge_bytes: 16,
                    payload_bytes: 8,
                    resident_bytes: 55,
                },
                &frontier_input,
                8_192,
                0.0,
                0.0,
            )
            .expect_err("mismatched resident byte envelope should fail before CUDA planning"),
            CudaTokenFactFrontierExecutionError::ResidentGraphByteEnvelopeMismatch {
                expected_bytes: 56,
                actual_bytes: 55,
            }
        );
    }

    #[test]
    fn planner_accounts_warm_resident_graph_without_upload_pressure() {
        let graph = plan_device_resident_token_fact_graph(
            &[node(1, TokenFactNodeKind::Token, 0, 16)],
            &[],
            16,
        )
        .expect("Fix: token/fact graph should pack");
        let graph_layout = adapt_token_fact_graph_to_cuda_layout(&graph, 32, 16)
            .expect("Fix: token/fact graph should adapt");
        let frontier_input = CudaFrontierTypedIrInput {
            waves: Vec::new(),
            active_items: Vec::new(),
            dependencies: Vec::new(),
        };
        let mut cache = CudaMegakernelPlanCache::new();

        let cold = plan_cuda_token_fact_frontier_execution_envelope(
            &mut cache,
            0xfeed,
            CudaMegakernelAnalysisKind::ParserFrontend,
            device(),
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1.0,
                frontier_density: 0.0,
                readback_bytes: 0,
            },
            graph_layout,
            CudaTokenFactGraphResidency::ColdUpload,
            &frontier_input,
            8_192,
            0.0,
            0.0,
        )
        .expect("Fix: cold token/fact graph should plan");
        let warm = plan_cuda_token_fact_frontier_execution_envelope(
            &mut cache,
            0xfeed,
            CudaMegakernelAnalysisKind::ParserFrontend,
            device(),
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1.0,
                frontier_density: 0.0,
                readback_bytes: 0,
            },
            graph_layout,
            CudaTokenFactGraphResidency::WarmResident,
            &frontier_input,
            8_192,
            0.0,
            0.0,
        )
        .expect("Fix: warm token/fact graph should plan");

        assert_eq!(cold.resident_graph_bytes, 32);
        assert_eq!(cold.graph_upload_bytes, 32);
        assert_eq!(cold.avoided_graph_upload_bytes, 0);
        assert_eq!(
            cold.graph_reuse,
            ResidentGraphReuseTelemetry::cold_upload(32)
        );
        assert_eq!(warm.resident_graph_bytes, 32);
        assert_eq!(warm.graph_upload_bytes, 0);
        assert_eq!(warm.avoided_graph_upload_bytes, 32);
        assert_eq!(
            warm.graph_reuse,
            ResidentGraphReuseTelemetry::warm_reuse(32)
        );
        assert_eq!(warm.total_resident_bytes, cold.total_resident_bytes);
    }

    #[test]
    fn planner_rejects_frontier_waves_without_matching_active_item_counts() {
        let graph = plan_device_resident_token_fact_graph(
            &[node(1, TokenFactNodeKind::Token, 0, 16)],
            &[],
            16,
        )
        .expect("Fix: token/fact graph should pack");
        let graph_layout = adapt_token_fact_graph_to_cuda_layout(&graph, 32, 16)
            .expect("Fix: token/fact graph should adapt");
        let frontier_input = CudaFrontierTypedIrInput {
            waves: vec![
                crate::megakernel_barrier_planner::CudaMegakernelFrontierWave {
                    frontier_bytes: 8,
                    scratch_bytes: 8,
                    output_bytes: 8,
                },
            ],
            active_items: Vec::new(),
            dependencies: Vec::new(),
        };
        let mut cache = CudaMegakernelPlanCache::new();

        assert_eq!(
            plan_cuda_token_fact_frontier_execution(
                &mut cache,
                0xfeed,
                CudaMegakernelAnalysisKind::ParserFrontend,
                device(),
                CudaMegakernelScheduleSample {
                    dispatch_cost_ns: 1.0,
                    frontier_density: 0.0,
                    readback_bytes: 0,
                },
                graph_layout,
                &frontier_input,
                8_192,
                0.0,
                0.0,
            )
            .expect_err("mismatched active-item counts should fail before queue planning"),
            CudaTokenFactFrontierExecutionError::ActiveItemWaveCountMismatch {
                waves: 1,
                active_items: 0,
            }
        );
    }

    #[test]
    fn planner_does_not_allocate_resident_work_queue_for_empty_frontier() {
        let graph = plan_device_resident_token_fact_graph(
            &[node(1, TokenFactNodeKind::Token, 0, 16)],
            &[],
            16,
        )
        .expect("Fix: token/fact graph should pack");
        let graph_layout = adapt_token_fact_graph_to_cuda_layout(&graph, 32, 16)
            .expect("Fix: token/fact graph should adapt");
        let frontier_input = CudaFrontierTypedIrInput {
            waves: Vec::new(),
            active_items: Vec::new(),
            dependencies: Vec::new(),
        };
        let mut cache = CudaMegakernelPlanCache::new();

        let plan = plan_cuda_token_fact_frontier_execution(
            &mut cache,
            0xfeed,
            CudaMegakernelAnalysisKind::ParserFrontend,
            device(),
            CudaMegakernelScheduleSample {
                dispatch_cost_ns: 1.0,
                frontier_density: 0.0,
                readback_bytes: 0,
            },
            graph_layout,
            &frontier_input,
            8_192,
            0.0,
            0.0,
        )
        .expect("Fix: empty frontier should not need a resident work queue");

        assert_eq!(plan.work_queue.queue_bytes, 0);
        assert_eq!(plan.work_queue.control_bytes, 0);
        assert_eq!(plan.resident_work_queue_bytes, 0);
        assert!(plan.work_queue.final_only_host_sync);
    }

    fn node(
        id: u32,
        kind: TokenFactNodeKind,
        payload_offset: u64,
        payload_bytes: u64,
    ) -> TokenFactNode {
        TokenFactNode {
            id,
            kind,
            payload_offset,
            payload_bytes,
        }
    }

    fn edge(from: u32, to: u32, kind: TokenFactEdgeKind) -> TokenFactEdge {
        TokenFactEdge { from, to, kind }
    }

    fn frontier_node(id: u32, domain: FrontierDomain, active_items: u32) -> FrontierNode {
        FrontierNode {
            id,
            domain,
            active_items,
        }
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

