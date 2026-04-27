//! Persistent megakernel — the GPU becomes a VIR0 bytecode interpreter.
//!
//! One dispatch compiles the program; the kernel loops forever, pulling
//! packed bytecode slots from a host-fed ring buffer and executing each.
//! The host never re-dispatches — it only writes new slots and observes
//! atomic counters in the control buffer.
//!
//! ## Layout
//!
//! - `protocol` — ring-buffer slot layout, control words, opcodes.
//! - `handlers` — built-in opcode handlers + extension mechanism.
//! - `builder` — IR `Program` construction (interpreted + JIT).
//!
//! ## Coordination protocol
//!
//! 1. Read `control[SHUTDOWN]`; if non-zero, `Node::Return`.
//! 2. Read this slot's `tenant_id`; authorize via tenant-mask table.
//! 3. CAS `ring_buffer[status]` from PUBLISHED → CLAIMED.
//! 4. Dispatch on opcode through If-tree (or JIT fused body).
//! 5. `atomic_add(control[DONE_COUNT], 1)`.
//! 6. Store DONE into the status word.

#[cfg(feature = "megakernel-batch")]
pub mod advanced;
#[cfg(feature = "megakernel-batch")]
pub mod batch;
pub mod builder;
pub mod c_frontend;
pub mod descriptor;
#[cfg(feature = "megakernel-batch")]
pub mod dispatcher;
pub mod handlers;
pub mod io;
pub mod protocol;
mod protocol_api;
#[cfg(feature = "megakernel-batch")]
pub mod rule_catalog;
pub mod scaling;
pub mod scheduler;
pub mod telemetry;
pub mod wgpu_dispatch;

use crate::PipelineError;
use protocol_api::{validate_control_bytes, validate_debug_log_bytes};
use std::sync::Arc;
use vyre_driver::backend::{CompiledPipeline, DispatchConfig, VyreBackend};

// Re-export protocol constants at the megakernel level for back-compat.
#[cfg(feature = "megakernel-batch")]
pub use batch::{
    queue_state_word, BatchFile, FileBatch, FileMetadata, HitRecord, WorkTriple,
    FILE_METADATA_WORDS, HIT_RECORD_WORDS, QUEUE_STATE_WORDS, WORK_TRIPLE_WORDS,
};
pub use builder::{
    build_program, build_program_jit, build_program_jit_slots, build_program_priority,
    build_program_sharded, build_program_sharded_no_io, build_program_sharded_once_slots,
    build_program_sharded_slots, build_program_sharded_with_c_frontend_workspace,
    build_program_sharded_with_c_frontend_workspace_phases, build_program_sharded_with_io_polling,
    persistent_body, persistent_body_jit, persistent_body_priority,
};
pub use c_frontend::{
    c_frontend_advance_phase_nodes, c_frontend_fault_nodes, c_frontend_phase_dispatch_nodes,
    c_frontend_phase_machine_guard_nodes, c_frontend_workspace_bootstrap_nodes,
    is_valid_c_frontend_phase_transition, validate_c_frontend_phase_transition,
    CFrontendCapacityDiagnosticKind, CFrontendPhase, CFrontendPhaseHandler, CFrontendRegionId,
    CFrontendWorkspaceError, CFrontendWorkspaceLimits, CFrontendWorkspaceManifest,
    CFrontendWorkspaceRegion, C_FRONTEND_CONDITIONAL_WORDS, C_FRONTEND_DIAGNOSTIC_WORDS,
    C_FRONTEND_MACRO_WORDS, C_FRONTEND_MANIFEST_WORDS, C_FRONTEND_PG_EDGE_WORDS,
    C_FRONTEND_TOKEN_WORDS, C_FRONTEND_VAST_ROW_WORDS, C_FRONTEND_WORKSPACE_ABI_VERSION,
    C_FRONTEND_WORKSPACE_BINDING, C_FRONTEND_WORKSPACE_BUFFER, C_FRONTEND_WORKSPACE_MAGIC,
    C_FRONTEND_WORK_QUEUE_WORDS, MAX_C_FRONTEND_WORKSPACE_WORDS,
};
pub use descriptor::{
    BatchDescriptor, BuiltinOpcode, PackedOpDescriptor, SlotDescriptor, SlotOpcode, WindowClass,
    WindowDescriptor,
};
#[cfg(feature = "megakernel-batch")]
pub use dispatcher::{BatchDispatchConfig, BatchDispatchReport, BatchDispatcher, BatchHitWriter};
pub use handlers::OpcodeHandler;
pub use io::{IoCompletion, IoRequest, MegakernelIoQueue, IO_SLOT_COUNT, IO_SLOT_WORDS};
pub use protocol::{
    control, control_byte_len, debug, debug_log_byte_len, encode_control, encode_empty_debug_log,
    encode_empty_ring, opcode, read_debug_log, read_done_count, read_epoch, read_metrics,
    read_observable, ring_byte_len, slot, try_encode_control, try_encode_empty_debug_log,
    try_encode_empty_ring, try_read_debug_log, try_read_done_count, try_read_epoch,
    try_read_metrics, try_read_observable, DebugRecord, ProtocolError, ARG0_WORD, ARGS_PER_SLOT,
    CONTROL_MIN_WORDS, OPCODE_WORD, PRIORITY_WORD, SLOT_WORDS, STATUS_WORD, TENANT_WORD,
};
#[cfg(feature = "megakernel-batch")]
pub use rule_catalog::{BatchRuleProgram, BatchRuleRejection};
pub use scaling::{
    MegakernelExecutionMode, MegakernelGridLimits, MegakernelGridPlan, MegakernelGridRequest,
    MegakernelLaunchGeometry, MegakernelLaunchPolicy, MegakernelLaunchRecommendation,
    MegakernelLaunchRequest, MegakernelQueuePressure, PriorityRequeueAccounting,
};
pub use scheduler::{default_priority_offsets, priority_scan_body, write_default_priority_offsets};
pub use telemetry::{
    ControlSnapshot, CountMinSketch, RingOccupancy, RingSlotSnapshot, RingStatus, RingTelemetry,
    SketchTelemetry, WindowTelemetry,
};
pub use wgpu_dispatch::WgpuMegakernelDispatcher;

/// Orchestrated persistent-megakernel handle.
///
/// Construct with [`Megakernel::bootstrap`] (default 256 lanes × 1
/// workgroup) or [`Megakernel::bootstrap_sharded`] for multi-tenant
/// fan-in. Feed bytecode with [`Megakernel::dispatch`].
pub struct Megakernel {
    pipeline: Arc<dyn CompiledPipeline>,
    slot_count: u32,
    workgroup_size_x: u32,
}

impl Megakernel {
    /// Default bootstrap: 256 lanes × 1 workgroup, no custom opcodes.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::Backend`] if the backend rejects the
    /// program (validation failure, unsupported feature, OOM).
    pub fn bootstrap(backend: Arc<dyn VyreBackend>) -> Result<Self, PipelineError> {
        Self::bootstrap_sharded(backend, 256, 256, Vec::new())
    }

    /// Bootstrap with custom opcodes but default sharding.
    ///
    /// # Errors
    ///
    /// See [`Megakernel::bootstrap`].
    pub fn bootstrap_with_opcodes(
        backend: Arc<dyn VyreBackend>,
        opcodes: Vec<OpcodeHandler>,
    ) -> Result<Self, PipelineError> {
        Self::bootstrap_sharded(backend, 256, 256, opcodes)
    }

    /// Full bootstrap with sharding and custom opcodes.
    ///
    /// # Errors
    ///
    /// - [`PipelineError::QueueFull`] if `slot_count` is not a
    ///   multiple of `workgroup_size_x` or either is zero.
    /// - [`PipelineError::Backend`] from the underlying compile.
    pub fn bootstrap_sharded(
        backend: Arc<dyn VyreBackend>,
        slot_count: u32,
        workgroup_size_x: u32,
        opcodes: Vec<OpcodeHandler>,
    ) -> Result<Self, PipelineError> {
        let program = build_program_sharded_slots(workgroup_size_x, slot_count, &opcodes);
        Self::compile_bootstrap(backend, slot_count, workgroup_size_x, program)
    }

    /// JIT Compiler Bootstrap (After Effects).
    ///
    /// Instead of interpreting primitive ops dynamically via an If-tree,
    /// this embeds the `payload_processor` nodes directly into the
    /// Megakernel for zero-divergence, high-intensity streaming.
    ///
    /// # Errors
    ///
    /// See [`Megakernel::bootstrap`].
    pub fn bootstrap_jit(
        backend: Arc<dyn VyreBackend>,
        slot_count: u32,
        workgroup_size_x: u32,
        payload_processor: &[vyre_foundation::ir::Node],
    ) -> Result<Self, PipelineError> {
        let program = build_program_jit_slots(workgroup_size_x, slot_count, payload_processor);
        Self::compile_bootstrap(backend, slot_count, workgroup_size_x, program)
    }

    fn compile_bootstrap(
        backend: Arc<dyn VyreBackend>,
        slot_count: u32,
        workgroup_size_x: u32,
        program: vyre_foundation::ir::Program,
    ) -> Result<Self, PipelineError> {
        if slot_count == 0 || workgroup_size_x == 0 || slot_count % workgroup_size_x != 0 {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "slot_count must be a non-zero multiple of workgroup_size_x",
            });
        }
        let config = DispatchConfig::default();
        let pipeline = vyre_driver::pipeline::compile(backend, &program, &config)?;
        Ok(Self {
            pipeline,
            slot_count,
            workgroup_size_x,
        })
    }

    /// Dispatch a full storage buffer set: `control`, `ring_buffer`, `debug_log`, `io_queue`.
    ///
    /// The compiled megakernel `Program` declares four read/write buffers; the
    /// IO queue is always included so dispatch matches [`build_program_sharded`].
    /// This convenience path supplies an empty IO queue. Use
    /// [`Megakernel::dispatch_with_io_queue`] when the persistent kernel is
    /// consuming async NVMe → VRAM completions.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::Backend`] propagated from the backend.
    pub fn dispatch(
        &self,
        control_bytes: Vec<u8>,
        ring_bytes: Vec<u8>,
        debug_log_bytes: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, PipelineError> {
        let io_queue_bytes = io::try_encode_empty_io_queue(io::IO_SLOT_COUNT)?;
        self.dispatch_with_io_queue(control_bytes, ring_bytes, debug_log_bytes, io_queue_bytes)
    }

    /// Dispatch a full storage buffer set with a caller-supplied `io_queue`.
    ///
    /// This is the production path for host-fed async DMA completions: the
    /// caller owns the IO queue bytes and can pass the queue maintained by
    /// [`MegakernelIoQueue`] or the Linux `uring` ingest driver. Use
    /// [`Megakernel::dispatch`] when the kernel should run with an empty
    /// queue.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when any protocol buffer is malformed or when
    /// the backend dispatch fails.
    pub fn dispatch_with_io_queue(
        &self,
        control_bytes: Vec<u8>,
        ring_bytes: Vec<u8>,
        debug_log_bytes: Vec<u8>,
        io_queue_bytes: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, PipelineError> {
        validate_control_bytes(&control_bytes)?;
        validate_debug_log_bytes(&debug_log_bytes)?;
        io::validate_io_queue_bytes(&io_queue_bytes)?;
        let expected_ring_bytes = protocol::ring_byte_len(self.slot_count).ok_or_else(|| {
            PipelineError::Backend(
                "megakernel ring byte length overflowed usize. Fix: split the ring into smaller dispatch shards."
                    .to_string(),
            )
        })?;
        if ring_bytes.len() != expected_ring_bytes {
            return Err(PipelineError::Backend(format!(
                "megakernel ring buffer has {} bytes, expected {expected_ring_bytes} for {} slots. Fix: build ring bytes with Megakernel::encode_empty_ring(slot_count) for this handle.",
                ring_bytes.len(),
                self.slot_count
            )));
        }
        let mut config = DispatchConfig::default();
        config.grid_override = Some([self.worker_groups(), 1, 1]);
        config.workgroup_override = Some([self.workgroup_size_x, 1, 1]);
        let outputs = self.pipeline.dispatch_borrowed(
            &[
                control_bytes.as_slice(),
                ring_bytes.as_slice(),
                debug_log_bytes.as_slice(),
                io_queue_bytes.as_slice(),
            ],
            &config,
        )?;
        Ok(outputs)
    }

    /// Pipeline id from the backend — useful for logging / metrics.
    #[must_use]
    pub fn pipeline_id(&self) -> &str {
        self.pipeline.id()
    }

    /// Slot count this kernel was sharded for.
    #[must_use]
    pub fn slot_count(&self) -> u32 {
        self.slot_count
    }

    /// Workgroup size this kernel was compiled for.
    #[must_use]
    pub fn workgroup_size_x(&self) -> u32 {
        self.workgroup_size_x
    }

    /// Workgroup count needed to cover every ring slot.
    #[must_use]
    pub fn worker_groups(&self) -> u32 {
        self.slot_count / self.workgroup_size_x
    }
}
