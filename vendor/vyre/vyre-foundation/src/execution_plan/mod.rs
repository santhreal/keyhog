//! Substrate-neutral execution planning for performance and accuracy.

use std::ops::Range;

use crate::ir::{BufferAccess, DataType, MemoryKind, Node, Program};
use crate::program_caps::{self, RequiredCapabilities};
use crate::validate::{validate_with_options, ValidationOptions};

pub mod fusion;
mod policy;
mod strategy;
pub use policy::{PolicyRoute, SchedulingPolicy};
pub use strategy::{
    AccuracyStrategy, AutotuneStrategy, DispatchStrategy, FusionStrategy, LayoutStrategy,
    ProvenanceStrategy, ReadbackStrategy, StrategyPlan,
};

/// Concerns that vyre treats as first-class planning concerns.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum InnovationTrack {
    /// Fuse compatible top-level regions into one dispatch.
    WholeProgramFusion,
    /// Keep execution state GPU-resident across repeated dispatches.
    PersistentExecution,
    /// Run a shadow reference path when precision risk is high.
    DifferentialAccuracy,
    /// Measure shape variants before choosing a dispatch shape.
    ConformanceGuidedAutotune,
    /// Preserve provenance data on the GPU until the caller asks for it.
    GpuResidentProvenance,
    /// Compile buffer layout choices from Program metadata.
    DataLayoutCompiler,
    /// Avoid host readback for buffers the caller cannot observe.
    ReadbackMinimization,
}

/// One track's current recommendation for a program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackDecision {
    /// Planning concern being evaluated.
    pub track: InnovationTrack,
    /// Whether the track should be enabled for this Program.
    pub active: bool,
    /// Short stable explanation for the decision.
    pub reason: &'static str,
}

/// Complete execution plan extracted from a Program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionPlan {
    /// BLAKE3 hash of the canonical VIR wire encoding.
    pub program_fingerprint: [u8; 32],
    /// Capabilities required by this Program's nodes and expressions.
    pub required_capabilities: RequiredCapabilities,
    /// Fusion-related planning facts.
    pub fusion: FusionPlan,
    /// Buffer and readback planning facts.
    pub memory: MemoryPlan,
    /// Region/provenance planning facts.
    pub provenance: ProvenancePlan,
    /// Accuracy and shadow-reference planning facts.
    pub accuracy: AccuracyPlan,
    /// Autotuning planning facts.
    pub autotune: AutotunePlan,
    /// Concrete execution strategies derived from the plan facts.
    pub strategy: StrategyPlan,
    /// Per-track decisions used by dashboards and diagnostics.
    pub tracks: Vec<TrackDecision>,
}

impl ExecutionPlan {
    /// Return whether `track` is active in this plan.
    #[must_use]
    pub fn track_active(&self, track: InnovationTrack) -> bool {
        self.tracks
            .iter()
            .any(|decision| decision.track == track && decision.active)
    }
}

/// Errors that prevent building a trustworthy execution plan.
#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    /// Program validation or canonical wire encoding failed.
    #[error("non-canonical program: {source}")]
    NonCanonicalProgram {
        /// Original validation or serialization error.
        source: crate::error::Error,
    },
    /// An output buffer advertises a byte range outside its full allocation.
    #[error(
        "invalid output range for buffer {name}: {start}..{end} exceeds full size {full_size}. Fix: keep output byte ranges ordered and inside the declared buffer size."
    )]
    InvalidOutputRange {
        /// Buffer name.
        name: String,
        /// Inclusive start byte offset.
        start: usize,
        /// Exclusive end byte offset.
        end: usize,
        /// Full buffer size in bytes.
        full_size: u64,
    },
}

/// Build a backend-neutral execution plan with default validation options.
pub fn plan(program: &Program) -> Result<ExecutionPlan, PlanError> {
    plan_with_options(program, ValidationOptions::default())
}

/// Build a backend-neutral execution plan after validating with `options`.
pub fn plan_with_options(
    program: &Program,
    options: ValidationOptions<'_>,
) -> Result<ExecutionPlan, PlanError> {
    validate_program_for_plan(program, options)?;
    let required_capabilities = program_caps::scan(program);
    let fusion = fusion_plan(program);
    let memory = memory_plan(program)?;
    let program_fingerprint = canonical_program_fingerprint(program)?;
    let provenance = provenance_plan(program, &fusion);
    let accuracy = accuracy_plan(&required_capabilities, &provenance);
    let autotune = autotune_plan(program, &required_capabilities, &fusion);

    let strategy = StrategyPlan::from_parts(&fusion, &memory, &provenance, &accuracy, &autotune);
    let tracks = track_decisions(&fusion, &memory, &provenance, &accuracy, &autotune);

    Ok(ExecutionPlan {
        program_fingerprint,
        required_capabilities,
        fusion,
        memory,
        provenance,
        accuracy,
        autotune,
        strategy,
        tracks,
    })
}

fn validate_program_for_plan(
    program: &Program,
    options: ValidationOptions<'_>,
) -> Result<(), PlanError> {
    if options.backend.is_none()
        && options.backend_capabilities.is_none()
        && program.is_structurally_validated()
    {
        return Ok(());
    }
    let report = validate_with_options(program, options);
    if report.errors.is_empty() {
        return Ok(());
    }
    let messages = report
        .errors
        .iter()
        .map(|error| error.message().to_string())
        .collect::<Vec<_>>()
        .join("; ");
    Err(PlanError::NonCanonicalProgram {
        source: crate::error::Error::WireFormatValidation {
            message: format!(
                "canonical execution plan validation failed: {messages}. Fix: repair the Program before planning."
            ),
        },
    })
}

fn fusion_plan(program: &Program) -> FusionPlan {
    let stats = program.stats();
    let node_count = count_nodes(program.entry());
    FusionPlan {
        entry_op_id: program.entry_op_id().map(ToOwned::to_owned),
        top_level_regions: stats.top_level_regions as usize,
        node_count,
        batch_fusion_candidate: !program.is_non_composable_with_self()
            && program.is_top_level_region_wrapped(),
    }
}

fn count_nodes(nodes: &[Node]) -> usize {
    nodes
        .iter()
        .map(|node| {
            1 + match node {
                Node::If {
                    then, otherwise, ..
                } => count_nodes(then) + count_nodes(otherwise),
                Node::Loop { body, .. } | Node::Block(body) => count_nodes(body),
                Node::Region { body, .. } => count_nodes(body),
                _ => 0,
            }
        })
        .sum()
}

fn canonical_program_fingerprint(program: &Program) -> Result<[u8; 32], PlanError> {
    let wire = program
        .to_wire()
        .map_err(|source| PlanError::NonCanonicalProgram { source })?;
    Ok(*blake3::hash(&wire).as_bytes())
}

fn memory_plan(program: &Program) -> Result<MemoryPlan, PlanError> {
    let mut static_bytes = 0u64;
    let mut visible_readback_bytes = 0u64;
    let mut avoided_readback_bytes = 0u64;
    let mut buffers = Vec::new();
    for buffer in program.buffers() {
        let count = buffer.count();
        let elem_size = buffer.element().size_bytes().unwrap_or(4) as u64;
        let size = if count > 0 {
            Some(u64::from(count) * elem_size)
        } else {
            None
        };
        if let Some(s) = size {
            static_bytes += s;
        }
        let output_range = buffer.output_byte_range();
        if buffer.is_output() {
            let full_size = size.unwrap_or(0);
            if full_size == 0 {
                return Err(PlanError::NonCanonicalProgram {
                    source: crate::error::Error::WireFormatValidation {
                        message: format!(
                            "canonical execution plan requires static output buffer `{}` size. Fix: set BufferDecl::output(...).with_count(n) before planning.",
                            buffer.name()
                        ),
                    },
                });
            }
            let visible = if let Some(range) = output_range.clone() {
                if range.start > range.end || range.end as u64 > full_size {
                    return Err(PlanError::InvalidOutputRange {
                        name: buffer.name().to_string(),
                        start: range.start,
                        end: range.end,
                        full_size,
                    });
                }
                (range.end - range.start) as u64
            } else {
                full_size
            };
            visible_readback_bytes += visible;
            avoided_readback_bytes += full_size.saturating_sub(visible);
        }
        buffers.push(BufferPlan {
            name: buffer.name().to_string(),
            binding: buffer.binding(),
            access: buffer.access(),
            kind: buffer.kind(),
            element: buffer.element(),
            count: buffer.count(),
            static_size_bytes: size,
            output_range,
        });
    }
    Ok(MemoryPlan {
        buffers,
        static_bytes,
        dynamic_buffers: program.buffers().iter().filter(|b| b.count() == 0).count(),
        visible_readback_bytes,
        avoided_readback_bytes,
    })
}

fn provenance_plan(program: &Program, _fusion: &FusionPlan) -> ProvenancePlan {
    ProvenancePlan {
        top_level_region_wrapped: program.is_top_level_region_wrapped(),
        region_count: program.stats().region_count as usize,
        emit_region_trace: program.is_top_level_region_wrapped(),
    }
}

fn accuracy_plan(caps: &RequiredCapabilities, _provenance: &ProvenancePlan) -> AccuracyPlan {
    AccuracyPlan {
        shadow_reference_recommended: caps.subgroup_ops,
        reason: if caps.subgroup_ops {
            "subgroup semantics"
        } else {
            "baseline"
        },
    }
}

fn autotune_plan(
    program: &Program,
    _caps: &RequiredCapabilities,
    _fusion: &FusionPlan,
) -> AutotunePlan {
    let node_count = count_nodes(program.entry());
    let policy = SchedulingPolicy::standard();
    AutotunePlan {
        recommended: policy.recommend_autotune(node_count),
        parallel_region_size: program.parallel_region_size(),
        reason: if policy.recommend_autotune(node_count) {
            "large program"
        } else {
            "none"
        },
    }
}

fn track_decisions(
    fusion: &FusionPlan,
    memory: &MemoryPlan,
    _provenance: &ProvenancePlan,
    accuracy: &AccuracyPlan,
    autotune: &AutotunePlan,
) -> Vec<TrackDecision> {
    vec![
        track_decision(
            InnovationTrack::WholeProgramFusion,
            fusion.batch_fusion_candidate,
            "fusion",
        ),
        track_decision(
            InnovationTrack::PersistentExecution,
            SchedulingPolicy::standard().use_persistent_runtime(fusion.node_count),
            "persistent",
        ),
        track_decision(
            InnovationTrack::DifferentialAccuracy,
            accuracy.shadow_reference_recommended,
            accuracy.reason,
        ),
        track_decision(
            InnovationTrack::ConformanceGuidedAutotune,
            autotune.recommended,
            autotune.reason,
        ),
        track_decision(InnovationTrack::GpuResidentProvenance, false, "none"),
        track_decision(
            InnovationTrack::DataLayoutCompiler,
            memory.static_bytes > 0,
            "layout",
        ),
        track_decision(
            InnovationTrack::ReadbackMinimization,
            memory.avoided_readback_bytes > 0,
            "trimmed readback",
        ),
    ]
}

fn track_decision(track: InnovationTrack, active: bool, reason: &'static str) -> TrackDecision {
    TrackDecision {
        track,
        active,
        reason,
    }
}

/// Region-fusion facts extracted from the Program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FusionPlan {
    /// Optional stable op id for the entry region.
    pub entry_op_id: Option<String>,
    /// Number of top-level regions.
    pub top_level_regions: usize,
    /// Total statement-node count.
    pub node_count: usize,
    /// Whether the Program is eligible for batch fusion.
    pub batch_fusion_candidate: bool,
}

/// Memory allocation and readback facts extracted from buffers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryPlan {
    /// Per-buffer planning facts.
    pub buffers: Vec<BufferPlan>,
    /// Sum of statically declared buffer bytes.
    pub static_bytes: u64,
    /// Number of buffers whose size is known only from runtime inputs.
    pub dynamic_buffers: usize,
    /// Bytes that must be visible to the host after dispatch.
    pub visible_readback_bytes: u64,
    /// Bytes avoided by trimming readback ranges.
    pub avoided_readback_bytes: u64,
}

/// Planning facts for one declared buffer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BufferPlan {
    /// Buffer name.
    pub name: String,
    /// Binding number.
    pub binding: u32,
    /// Declared access mode.
    pub access: BufferAccess,
    /// Memory address space.
    pub kind: MemoryKind,
    /// Element type.
    pub element: DataType,
    /// Declared element count, or zero for runtime-sized buffers.
    pub count: u32,
    /// Static byte size when `count` is nonzero.
    pub static_size_bytes: Option<u64>,
    /// Caller-visible output byte range, when trimmed.
    pub output_range: Option<Range<usize>>,
}

/// Region/provenance facts used to decide trace strategy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenancePlan {
    /// Whether the entry is wrapped in canonical top-level regions.
    pub top_level_region_wrapped: bool,
    /// Total region count in the Program.
    pub region_count: usize,
    /// Whether the backend should emit a GPU-resident region trace.
    pub emit_region_trace: bool,
}

/// Accuracy strategy facts used for shadow-reference selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccuracyPlan {
    /// Whether a shadow reference pass is recommended.
    pub shadow_reference_recommended: bool,
    /// Stable reason for the recommendation.
    pub reason: &'static str,
}

/// Autotuning facts used for dispatch shape selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutotunePlan {
    /// Whether the backend should measure variants.
    pub recommended: bool,
    /// Declared parallel region size.
    pub parallel_region_size: [u32; 3],
    /// Stable reason for the recommendation.
    pub reason: &'static str,
}
