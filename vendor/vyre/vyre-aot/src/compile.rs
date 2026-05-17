//! Program → CompiledArtifact lowering.
//!
//! The compile path asks the `vyre-driver` AOT registry for a linked
//! target emitter and packs the resulting bytes plus binding/dispatch
//! metadata into a [`CompiledArtifact`].

use thiserror::Error;
use vyre_foundation::ir::{inline_calls_with_resolver, OpResolver, Program};

use crate::artifact::{
    BufferAccessKind, BufferEntry, BufferMemoryKind, CompiledArtifact, DispatchGeometry, Target,
};
use crate::VERSION;

/// Errors returned by [`compile`].
#[derive(Debug, Error)]
pub enum CompileError {
    /// The chosen `Target` is not enabled in this build (feature flag).
    #[error(
        "vyre-aot: target {0:?} has no linked AOT emitter. Fix: link the concrete driver crate that owns this target."
    )]
    TargetNotEnabled(Target),

    /// The backend rejected the Program with a structured message.
    #[error("vyre-aot: backend rejected Program: {0}")]
    BackendError(String),
}

/// Compile a `Program` into a self-contained artifact for a chosen target.
///
/// This is the load-bearing entry point. All vyre-foundation / vyre-driver
/// machinery is touched HERE; the resulting [`CompiledArtifact`] is
/// self-describing and the launcher does not need vyre at runtime.
///
/// # Errors
///
/// Returns [`CompileError::TargetNotEnabled`] if the requested target's
/// feature flag is not enabled, or [`CompileError::BackendError`] if the
/// backend rejects the Program.
pub fn compile(program: &Program, target: Target) -> Result<CompiledArtifact, CompileError> {
    compile_with_resolver(program, target, None)
}

/// Compile with a caller-supplied resolver to inline `Expr::Call` nodes.
///
/// When the input Program contains `Expr::Call` to ops registered through
/// `vyre-driver`'s `DialectRegistry` or `vyre-libs::harness::OpEntry`, supply
/// an [`OpResolver`] (an `fn(&str) -> Option<Program>`) so the inline pass
/// can substitute their bodies before backend emission. Pass `None` if the
/// Program has no `Expr::Call` nodes (e.g. low-level smoke tests).
///
/// # Errors
///
/// Same as [`compile`], plus inline-pass errors when the Program has
/// unresolvable calls.
pub fn compile_with_resolver(
    program: &Program,
    target: Target,
    resolver: Option<OpResolver>,
) -> Result<CompiledArtifact, CompileError> {
    // AOT emitters need a Program with no `Expr::Call` nodes — run
    // inline_calls when a resolver is provided, otherwise pass through
    // unchanged (the caller has either pre-inlined or guarantees no Call).
    let inlined = match resolver {
        Some(r) => inline_calls_with_resolver(program, r)
            .map_err(|e| CompileError::BackendError(format!("{e:?}")))?,
        None => program.clone(),
    };

    // P-AOT-2: run the canonical optimizer pipeline (canonicalize →
    // region_inline → CSE → DCE) so AOT and JIT produce identical
    // post-optimization Programs for identical inputs. This is the
    // single seam where every recursion-thesis self-consumer wired
    // into `vyre_foundation::optimizer::pre_lowering::optimize` (categorical
    // pass scheduler, tensor-network fusion order, dataflow fixpoint,
    // submodular cache eviction, etc.) flows into the AOT compile
    // path. Pre-fix: AOT bypassed all optimization and emitted bytecode
    // directly from the inlined Program. Post-fix: AOT inherits every
    // substrate upgrade landed in vyre-foundation for free.
    let optimized = vyre_foundation::ir::optimize(inlined);

    // P-AOT-1: AOT artifacts carry a VSA fingerprint of the optimized
    // Program for downstream cache-dedup. Two compilations that
    // differ only in non-semantic detail (instruction order,
    // commutative-operand ordering) collide on the same VSA
    // fingerprint, letting AOT toolchains skip redundant emit.
    // Computed via the substrate vsa_fingerprint primitive — the
    // same approximate-match cache key that driver validation caches
    // use, so AOT and JIT share artifact-identity.
    let vsa = vyre_self_substrate::vsa_fingerprint::vsa_fingerprint_cpu(&optimized);

    let buffers = collect_buffer_entries(&optimized);

    let dispatch_config = vyre_driver::DispatchConfig::default();
    let kernel_bytes =
        vyre_driver::aot::emit_aot_target(target.aot_target_id(), &optimized, &dispatch_config)
            .map_err(|error| match error {
                vyre_driver::BackendError::UnsupportedFeature { .. } => {
                    CompileError::TargetNotEnabled(target)
                }
                other => CompileError::BackendError(other.to_string()),
            })?;

    let dispatch = DispatchGeometry {
        workgroup_size: optimized.workgroup_size,
        // Grid size of [0; 3] is the convention for "host computes from control".
        grid_size: [0, 0, 0],
        dynamic_shared_bytes: 0,
    };

    Ok(CompiledArtifact {
        target,
        kernel_bytes,
        entry_point: "main".to_string(),
        buffers,
        dispatch,
        aot_version: VERSION.to_string(),
        vsa_fingerprint: vsa,
    })
}

fn collect_buffer_entries(program: &Program) -> Vec<BufferEntry> {
    program
        .buffers()
        .iter()
        .map(|buf| BufferEntry {
            name: buf.name().to_string(),
            binding: buf.binding(),
            element_count: buf.count(),
            element_size_bytes: element_size_bytes(buf.element()),
            memory_kind: convert_memory_kind(buf.kind()),
            access: convert_access(buf.access()),
        })
        .collect()
}

fn element_size_bytes(ty: vyre_foundation::ir::DataType) -> u32 {
    use vyre_foundation::ir::DataType;
    match ty {
        DataType::Bool => 1,
        DataType::U8 | DataType::I8 => 1,
        DataType::U16 | DataType::I16 | DataType::F16 | DataType::BF16 => 2,
        DataType::U32 | DataType::I32 | DataType::F32 => 4,
        DataType::U64 | DataType::I64 | DataType::F64 => 8,
        // Bytes/struct/opaque: caller must supply size; default to 4.
        _ => 4,
    }
}

fn convert_memory_kind(k: vyre_foundation::ir::MemoryKind) -> BufferMemoryKind {
    use vyre_foundation::ir::MemoryKind;
    match k {
        MemoryKind::Shared | MemoryKind::Local => BufferMemoryKind::Shared,
        MemoryKind::Uniform | MemoryKind::Push | MemoryKind::Readonly => BufferMemoryKind::Constant,
        _ => BufferMemoryKind::Global,
    }
}

fn convert_access(a: vyre_foundation::ir::BufferAccess) -> BufferAccessKind {
    use vyre_foundation::ir::BufferAccess;
    match a {
        BufferAccess::ReadOnly => BufferAccessKind::ReadOnly,
        BufferAccess::WriteOnly => BufferAccessKind::WriteOnly,
        BufferAccess::ReadWrite => BufferAccessKind::ReadWrite,
        _ => BufferAccessKind::ReadWrite,
    }
}
