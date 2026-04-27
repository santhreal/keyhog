//! Backend-owned lowering for wgpu.
//!
//! Core IR is substrate-neutral. This module is the only place the wgpu
//! backend turns a [`vyre::Program`] into Naga IR and, at the last boundary,
//! WGSL source accepted by `wgpu`.

/// Cross-dispatch kernel fusion pass (C-B8).
///
/// Pure analysis: given an (upstream, downstream) pair and adapter
/// caps, decide whether the two kernels can be collapsed into one
/// ComputePipeline. The stitching happens in the dispatch lowering
/// pipeline when this pass returns `FusionDecision::Accept`.
pub mod fusion;
pub mod naga_emit;
/// Shader specialization constants (C-B3).
///
/// Op attributes that are literal `u32` / `i32` / `f32` become naga
/// `Override` constants, specialized per call via
/// `ComputePipelineDescriptor::constants`. Pipeline cache key
/// extends to include the specialization values so distinct spec
/// triples don't collide.
pub mod specialization;
/// Subgroup-op intrinsics (C-B2).
///
/// Wires `wgpu::Features::SUBGROUP` into reduce / scan / shuffle /
/// histogram lowerings. Emits `subgroupBroadcast` / `subgroupAdd`
/// / `subgroupMax` / `subgroupInclusiveAdd` / `subgroupShuffleXor`
/// when available; otherwise emits the shared-memory scan path.
pub mod subgroup_intrinsics;

use crate::WgpuBackend;
use naga::valid::{Capabilities, ValidationFlags, Validator};
use std::sync::Arc;
use vyre_foundation::lower::LoweringError;

/// Binding assignment made by the wgpu lowering pipeline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WgpuBindingAssignment {
    /// Program buffer name.
    pub name: Arc<str>,
    /// Bind group index. Vyre wgpu programs currently use group 0.
    pub group: u32,
    /// Binding slot inside the group.
    pub binding: u32,
    /// Memory tier used to choose the wgpu address space.
    pub kind: vyre::ir::MemoryKind,
    /// Access mode declared by core IR.
    pub access: vyre::ir::BufferAccess,
    /// Element type carried by the binding.
    pub element: vyre::ir::DataType,
}

/// Dispatch geometry captured during backend IR lowering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WgpuDispatchGeometry {
    /// Shader workgroup size.
    pub workgroup_size: [u32; 3],
    /// Static x workgroup count when it is derivable from output shape.
    pub workgroups: [u32; 3],
}

/// Backend-owned wgpu IR.
#[derive(Clone, Debug)]
pub struct WgpuProgram {
    /// Structurally emitted Naga module.
    pub module: naga::Module,
    /// Resource binding decisions.
    pub bindings: Vec<WgpuBindingAssignment>,
    /// Workgroup sizing chosen for the shader entry point.
    pub workgroup_size: [u32; 3],
    /// Dispatch geometry derived from program output declarations.
    pub dispatch_geometry: WgpuDispatchGeometry,
}

/// Lower a certified program to WGSL.
///
/// The shader text is produced only after structural Naga IR construction and
/// validation. Callers that need the module itself should use
/// [`naga_emit::emit_module`].
///
/// # Errors
///
/// Returns [`LoweringError`] when the program cannot be represented in Naga,
/// validation fails, or the final writer fails.
#[inline]
pub fn lower(program: &vyre::Program) -> Result<String, LoweringError> {
    lower_with_config(program, &vyre::DispatchConfig::default())
}

/// Lower a program to WGSL with explicit dispatch policy.
///
/// # Errors
///
/// Returns [`LoweringError`] for invalid IR, failed Naga validation, or failed
/// WGSL writing.
pub fn lower_with_config(
    program: &vyre::Program,
    config: &vyre::DispatchConfig,
) -> Result<String, LoweringError> {
    let default_features = crate::runtime::device::EnabledFeatures::default();
    lower_with_features(program, config, &default_features)
}

/// Lower a program to WGSL with explicit dispatch policy and adapter features.
///
/// # Errors
///
/// Returns [`LoweringError`] for invalid IR, failed Naga validation, or failed
/// WGSL writing.
pub(crate) fn lower_with_features(
    program: &vyre::Program,
    config: &vyre::DispatchConfig,
    enabled_features: &crate::runtime::device::EnabledFeatures,
) -> Result<String, LoweringError> {
    let bir = WgpuProgram::from_program(program, config, enabled_features)?;
    write_wgsl(&bir.module)
}

/// Heuristic for selecting the optimal workgroup size for a program.
///
/// Innovation I.6: Adaptive workgroup sizing.
///
/// Takes the requested size from the program and the adapter capability
/// reports, and returns a size that maximizes occupancy and throughput.
/// Multi-axis workgroups are flattened to 1D [N, 1, 1] for current
/// scan-based vyre opcodes.
pub(crate) fn optimal_workgroup_size(
    program: &vyre::Program,
    enabled_features: &crate::runtime::device::EnabledFeatures,
) -> [u32; 3] {
    let requested = program.workgroup_size;

    // If the program specified a non-default concrete size, honor it.
    // [1, 1, 1] is the legacy scalar default used by many builders.
    if requested != [1, 1, 1] && requested != [0, 0, 0] {
        return requested;
    }

    // Heuristic: use a multiple of the subgroup size.
    // If unknown (0), default to 64.
    let subgroup = enabled_features.min_subgroup_size.max(32);
    let size = if program.is_explicit_noop() {
        1
    } else {
        // For scan-heavy workloads, 4x subgroup size often yields
        // good occupancy without hitting register pressure.
        (subgroup * 4).min(256)
    };

    let max_x = enabled_features.max_workgroup_size[0].max(1);
    [size.min(max_x), 1, 1]
}

impl WgpuProgram {
    /// Build backend IR from a core program.
    ///
    /// # Errors
    ///
    /// Returns [`LoweringError`] when the program cannot be represented as
    /// wgpu/Naga IR.
    pub fn from_program(
        program: &vyre::Program,
        config: &vyre::DispatchConfig,
        enabled_features: &crate::runtime::device::EnabledFeatures,
    ) -> Result<Self, LoweringError> {
        let workgroup_size = config
            .workgroup_override
            .unwrap_or_else(|| optimal_workgroup_size(program, enabled_features));
        let module = naga_emit::emit_module(program, config, workgroup_size)?;
        let bindings = binding_assignments(program);
        let dispatch_geometry = WgpuDispatchGeometry {
            workgroup_size,
            workgroups: static_workgroups(program, workgroup_size),
        };
        Ok(Self {
            module,
            bindings,
            workgroup_size,
            dispatch_geometry,
        })
    }
}

impl WgpuBackend {
    /// Lower core IR into the backend-owned wgpu IR.
    pub fn lower_to_backend_ir(
        &self,
        program: &vyre::Program,
    ) -> Result<WgpuProgram, LoweringError> {
        WgpuProgram::from_program(
            program,
            &vyre::DispatchConfig::default(),
            &self.enabled_features,
        )
    }

    /// Lower backend IR into a validated Naga module.
    pub fn lower_to_target(&self, bir: &WgpuProgram) -> Result<naga::Module, LoweringError> {
        Ok(bir.module.clone())
    }
}

fn write_wgsl(module: &naga::Module) -> Result<String, LoweringError> {
    let mut validator = Validator::new(ValidationFlags::all(), Capabilities::all());
    let info = match validator.validate(module) {
        Ok(info) => info,
        Err(e) => {
            // VYRE_NAGA_LOWER MEDIUM: replace `println!` with
            // structured tracing so shader constants and buffer
            // layouts don't leak to application stdout. `trace!`
            // level keeps the diagnostic available under
            // `RUST_LOG=vyre_driver_wgpu=trace` without shipping
            // it to normal logs.
            if let Some(func) = module.functions.iter().next() {
                tracing::trace!(
                    target: "vyre_driver_wgpu::naga",
                    function_expressions = ?func.1.expressions,
                    "naga validation failed — function expressions",
                );
            }
            if let Some(ep) = module.entry_points.first() {
                tracing::trace!(
                    target: "vyre_driver_wgpu::naga",
                    entrypoint_expressions = ?ep.function.expressions,
                    "naga validation failed — entrypoint expressions",
                );
            }
            return Err(LoweringError::validation(e));
        }
    };
    let wgsl =
        naga::back::wgsl::write_string(module, &info, naga::back::wgsl::WriterFlags::empty())
            .map_err(LoweringError::writer)?;
    // Emission size cap (Task #65): adapter shader-binary-size limits
    // are finite. At 1000+ fused arms WGSL source can exceed the
    // ceiling. Fail-fast at write_wgsl with a clear diagnostic
    // naming the byte count, instead of opaque pipeline-creation
    // failure downstream. The 32 MiB cap below is the safe floor —
    // most adapters allow 256 MiB but Metal-on-iOS is the strictest.
    // Production adapters report their limit via wgpu::Limits; if the
    // FusionPlan partitioning harness is wired (Task #65 callers),
    // it consults the adapter limit and partitions before reaching
    // here. This guard is the last-line failsafe.
    const MAX_WGSL_BYTES: usize = 32 * 1024 * 1024;
    if wgsl.len() > MAX_WGSL_BYTES {
        return Err(LoweringError::invalid(format!(
            "emitted WGSL is {} bytes, exceeding the {MAX_WGSL_BYTES}-byte safety cap. Fix: partition the FusionPlan into multiple megakernels (group_a / group_b / ...) with shared standard pack, or split the source Program into smaller compilation units. Adapter shader-binary-size limits are finite at scale.",
            wgsl.len()
        )));
    }
    Ok(wgsl)
}

fn binding_assignments(program: &vyre::Program) -> Vec<WgpuBindingAssignment> {
    program
        .buffers()
        .iter()
        .filter(|buffer| buffer.kind() != vyre::ir::MemoryKind::Shared)
        .map(|buffer| WgpuBindingAssignment {
            name: Arc::from(buffer.name()),
            group: bind_group_for(buffer.kind()),
            binding: buffer.binding(),
            kind: buffer.kind(),
            access: buffer.access(),
            element: buffer.element(),
        })
        .collect()
}

/// Map a core IR memory kind to a wgpu bind-group index.
///
/// Before 0.6 the wgpu lowering hardcoded group 0 for every binding,
/// so bindless resources, per-draw uniforms, and push-constant-like
/// fast-rebind slots could not live in their own group without
/// editing the lowering. This function is the sole authority on
/// group placement: changing it propagates through the emitter
/// (naga_emit) and the reflection helper (pipeline_bindings) in
/// lockstep.
///
/// Current policy: storage-like resources stay in group 0, while
/// Uniform/Push metadata lives in group 1. Pipeline creation derives
/// every required `BindGroupLayout` from this same policy, and Naga
/// emission calls this function when assigning WGSL `@group` values,
/// so resource-frequency partitioning is wired instead of documented
/// as a future-only path.
#[must_use]
pub(crate) fn bind_group_for(kind: vyre::ir::MemoryKind) -> u32 {
    match kind {
        // V7-CORR-018: split uniforms into group 1 to reduce root-signature
        // churn on backends that benefit from frequency partitioning.
        // Group 0 contains storage buffers (data); group 1 contains
        // parameters/uniforms (metadata).
        vyre::ir::MemoryKind::Uniform | vyre::ir::MemoryKind::Push => 1,
        _ => 0,
    }
}

fn static_workgroups(program: &vyre::Program, workgroup_size: [u32; 3]) -> [u32; 3] {
    let output_words = program
        .output_buffer_indices()
        .iter()
        .filter_map(|&index| program.buffers().get(index as usize))
        .map(|buffer| buffer.count().max(1))
        .max()
        .unwrap_or(1);
    let lanes = workgroup_size[0].max(1);
    [output_words.div_ceil(lanes).max(1), 1, 1]
}
