use super::{AccuracyPlan, AutotunePlan, FusionPlan, MemoryPlan, ProvenancePlan, SchedulingPolicy};

/// Strategy for whole-program fusion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FusionStrategy {
    /// Program is a candidate for fusion with upstream/downstream neighbors.
    Candidate,
    /// Program must execute as an isolated dispatch.
    Isolated,
}

/// Strategy for kernel dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchStrategy {
    /// Execute as a standard one-shot compiled pipeline.
    CompiledPipeline,
    /// Execute as a work-item in a persistent megakernel runtime.
    PersistentRuntime,
}

/// Strategy for accuracy verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccuracyStrategy {
    /// Execute directly without shadow checks.
    Direct,
    /// Run a shadow reference interpreter for high-risk transcendental ops.
    ShadowReference,
}

/// Strategy for hardware-aware autotuning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutotuneStrategy {
    /// Use the declared workgroup size / sharding policy.
    DeclaredShape,
    /// Measure multiple workgroup size variants before choosing a target.
    MeasureVariants,
}

/// Strategy for execution provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvenanceStrategy {
    /// Track minimal required metadata.
    Minimal,
    /// Generate a detailed GPU execution trace for every opcode.
    GpuTrace,
}

/// Strategy for buffer layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutStrategy {
    /// Program has no declared buffers.
    Empty,
    /// All buffer sizes are statically declared.
    Static,
    /// At least one buffer size comes from runtime input data.
    Dynamic,
}

/// Strategy for host readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadbackStrategy {
    /// Read back the full visible output size.
    Full {
        /// Number of bytes read.
        bytes: u64,
    },
    /// Read back only the caller-visible byte range.
    Trimmed {
        /// Bytes copied to the caller.
        visible_bytes: u64,
        /// Bytes skipped by trimming.
        avoided_bytes: u64,
    },
}

impl ReadbackStrategy {
    /// Number of bytes the host will observe after applying this readback strategy.
    #[must_use]
    pub fn visible_bytes(&self) -> u64 {
        match self {
            Self::Full { bytes } => *bytes,
            Self::Trimmed { visible_bytes, .. } => *visible_bytes,
        }
    }
}

/// Concrete strategy selections derived from an execution plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrategyPlan {
    /// Fusion strategy.
    pub fusion: FusionStrategy,
    /// Dispatch strategy.
    pub dispatch: DispatchStrategy,
    /// Accuracy strategy.
    pub accuracy: AccuracyStrategy,
    /// Autotune strategy.
    pub autotune: AutotuneStrategy,
    /// Provenance strategy.
    pub provenance: ProvenanceStrategy,
    /// Layout strategy.
    pub layout: LayoutStrategy,
    /// Readback strategy.
    pub readback: ReadbackStrategy,
}

impl StrategyPlan {
    pub(super) fn from_parts(
        fusion: &FusionPlan,
        memory: &MemoryPlan,
        provenance: &ProvenancePlan,
        accuracy: &AccuracyPlan,
        autotune: &AutotunePlan,
    ) -> Self {
        let policy = SchedulingPolicy::standard();
        Self {
            fusion: if fusion.batch_fusion_candidate {
                FusionStrategy::Candidate
            } else {
                FusionStrategy::Isolated
            },
            dispatch: if policy.use_persistent_runtime(fusion.node_count) {
                DispatchStrategy::PersistentRuntime
            } else {
                DispatchStrategy::CompiledPipeline
            },
            accuracy: if accuracy.shadow_reference_recommended {
                AccuracyStrategy::ShadowReference
            } else {
                AccuracyStrategy::Direct
            },
            autotune: if autotune.recommended {
                AutotuneStrategy::MeasureVariants
            } else {
                AutotuneStrategy::DeclaredShape
            },
            provenance: if provenance.emit_region_trace {
                ProvenanceStrategy::GpuTrace
            } else {
                ProvenanceStrategy::Minimal
            },
            layout: if memory.dynamic_buffers > 0 {
                LayoutStrategy::Dynamic
            } else if memory.static_bytes > 0 {
                LayoutStrategy::Static
            } else {
                LayoutStrategy::Empty
            },
            readback: if memory.avoided_readback_bytes > 0 {
                ReadbackStrategy::Trimmed {
                    visible_bytes: memory.visible_readback_bytes,
                    avoided_bytes: memory.avoided_readback_bytes,
                }
            } else {
                ReadbackStrategy::Full {
                    bytes: memory.visible_readback_bytes,
                }
            },
        }
    }
}
