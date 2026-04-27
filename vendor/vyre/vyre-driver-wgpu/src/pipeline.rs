//! Native pipeline-mode implementation for the wgpu backend.
//!
//! P-6 from `docs/audits/ROADMAP_PERFORMANCE.md`. Pre-compiles WGSL,
//! compute pipeline, and bind-group layout once so subsequent dispatch
//! calls only pay buffer-allocation + execution + readback cost.
//!
//! Per the roadmap, this removes ~90% of per-call overhead — the WGSL
//! lowering and pipeline compilation costs dominate over the actual GPU
//! work for short programs run repeatedly.

use std::ops::ControlFlow::{self, Continue};
use std::sync::Arc;
use std::time::Instant;

use smallvec::SmallVec;
use vyre_driver::{BackendError, CompiledPipeline, DispatchConfig};
use vyre_foundation::execution_plan::{self, ExecutionPlan};
use vyre_foundation::ir::model::expr::GeneratorRef;
use vyre_foundation::ir::Program;
use vyre_foundation::validate::ValidationOptions;
use vyre_foundation::visit::{visit_node_preorder, NodeVisitor};

pub use crate::buffer::BindGroupCacheStats;
use crate::buffer::{BindGroupCache, StagingBufferPool};
use crate::lowering::naga_emit::{self, TrapTag, TRAP_SIDECAR_NAME, TRAP_SIDECAR_WORDS};
use crate::pipeline_disk_cache::{
    compiled_pipeline_cache_key, create_compiled_pipeline_cache, early_pipeline_cache_key,
    load_or_compile_disk_wgsl, persist_compiled_pipeline_cache,
};
pub use crate::pipeline_persistent::DispatchItem;
use crate::runtime;
use crate::DispatchArena;

/// Maximum entries retained in the pipeline cache.
/// Soft cap on the in-memory pipeline cache. Exposed so observability
/// reporting (see `WgpuBackend::stats`) can surface the capacity
/// alongside the live entry count.
pub const MAX_PIPELINE_CACHE_ENTRIES: usize = 256;

/// GPU pipeline + **all** per-program dispatch metadata co-located for
/// cache hits. A hit on [`early_pipeline_cache_key`] or the WGSL hash
/// key must skip `execution_plan::plan`, `output_layouts_from_program`,
/// and fresh [`StagingBufferPool::new`] (subagent: pipeline.rs compile
/// path — 2026-04 orchestration sweep).
#[derive(Debug)]
pub(crate) struct CachedPipelineArtifact {
    id: String,
    pipeline: Arc<wgpu::ComputePipeline>,
    bind_group_layouts: Arc<[Arc<wgpu::BindGroupLayout>]>,
    bind_group_cache: Arc<BindGroupCache>,
    /// Shared across every [`WgpuPipeline`] built from this artifact.
    pub(crate) execution_plan: Arc<ExecutionPlan>,
    pub(crate) output_bindings: Arc<[OutputBindingLayout]>,
    pub(crate) buffer_bindings: Arc<[BufferBindingInfo]>,
    pub(crate) output: OutputLayout,
    pub(crate) output_word_count: usize,
    pub(crate) workgroup_size: u32,
    pub(crate) indirect: Option<IndirectDispatch>,
    pub(crate) trap_tags: Arc<[TrapTag]>,
    /// Cloned per [`WgpuPipeline`]; all clones share the inner pool.
    pub(crate) staging_pool: StagingBufferPool,
}

/// In-memory pipeline cache (P-27 from `docs/audits/ROADMAP_PERFORMANCE.md`).
///
/// Keyed by a full program fingerprint (serialized IR + adapter fingerprint),
/// returned as `Arc` so multiple callers share one ComputePipeline.
/// `WgpuPipeline` is a thin wrapper around an `Arc<CachedPipeline>` plus
/// per-instance values (id, output_size).

/// Metadata for one buffer binding derived from a `Program` at compile time.
#[derive(Clone, Debug)]
pub(crate) struct BufferBindingInfo {
    /// `group N` slot.
    pub group: u32,
    /// `binding slot N` slot.
    pub binding: u32,
    /// Buffer name referenced by IR loads/stores.
    pub name: Arc<str>,
    /// Access mode.
    pub access: vyre::ir::BufferAccess,
    /// Memory tier.
    pub kind: vyre::ir::MemoryKind,
    /// Non-binding optimization hints.
    pub hints: vyre::ir::MemoryHints,
    /// Element type.
    pub element: vyre::ir::DataType,
    /// Static element count (`0` means runtime-sized).
    pub count: u32,
    /// Whether this binding is returned to the caller after dispatch.
    pub is_output: bool,
    /// Whether this writable binding must preserve caller-supplied initial bytes.
    pub preserve_input_contents: bool,
    /// Backend-owned trap sidecar; not supplied by callers and not returned as
    /// a public output.
    pub internal_trap: bool,
}

/// Readback and allocation metadata for one writable buffer.
#[derive(Clone, Debug)]
pub(crate) struct OutputBindingLayout {
    /// Buffer binding slot.
    pub binding: u32,
    /// Buffer name for diagnostics.
    pub name: Arc<str>,
    /// Full readback/copy layout for this binding.
    pub layout: OutputLayout,
    /// Rounded-up 32-bit word count used for allocation and clears.
    pub word_count: usize,
}

/// Cached state for a vyre program on the wgpu backend.
///
/// Built by `WgpuBackend::compile_native`.
/// Holds the compiled compute pipeline and the bind-group layout (both
/// derived from the WGSL lowering) plus the geometry needed to size each
/// dispatch's input/output buffers.
#[derive(Clone)]
pub struct WgpuPipeline {
    pub(crate) id: String,
    pub(crate) pipeline: Arc<wgpu::ComputePipeline>,
    pub(crate) bind_group_layouts: Arc<[Arc<wgpu::BindGroupLayout>]>,
    pub(crate) bind_group_cache: Arc<BindGroupCache>,
    pub(crate) buffer_bindings: Arc<[BufferBindingInfo]>,
    pub(crate) output_bindings: Arc<[OutputBindingLayout]>,
    pub(crate) execution_plan: Arc<ExecutionPlan>,
    pub(crate) device_queue: Arc<(wgpu::Device, wgpu::Queue)>,
    pub(crate) output: OutputLayout,
    pub(crate) output_word_count: usize,
    pub(crate) workgroup_size: u32,
    pub(crate) indirect: Option<IndirectDispatch>,
    pub(crate) trap_tags: Arc<[TrapTag]>,
    /// Shared persistent GPU-handle pool (H1). The legacy dispatch
    /// path acquires handles from here so repeated dispatches reuse
    /// `wgpu::Buffer` allocations instead of churning the GPU
    /// allocator on every call.
    pub(crate) persistent_pool: crate::buffer::BufferPool,
    /// Staging buffer pool for readback. Hot dispatch paths reuse
    /// MAP_READ staging buffers instead of creating a fresh
    /// `wgpu::Buffer` on every readback.
    pub(crate) staging_pool: StagingBufferPool,
}

impl std::fmt::Debug for WgpuPipeline {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WgpuPipeline")
            .field("id", &self.id)
            .field("buffer_bindings", &self.buffer_bindings)
            .field("output_bindings", &self.output_bindings)
            .field("execution_tracks", &self.execution_plan.tracks)
            .field("output", &self.output)
            .field("output_word_count", &self.output_word_count)
            .field("workgroup_size", &self.workgroup_size)
            .field("indirect", &self.indirect)
            .field("trap_tags", &self.trap_tags)
            .finish_non_exhaustive()
    }
}

/// Command-buffer indirect dispatch source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndirectDispatch {
    /// Buffer containing the indirect x/y/z workgroup tuple.
    pub count_buffer: String,
    /// Byte offset of the tuple in the buffer.
    pub count_offset: u64,
}

impl WgpuPipeline {
    fn from_cached_artifact(
        cached: &CachedPipelineArtifact,
        device_queue: Arc<(wgpu::Device, wgpu::Queue)>,
        persistent_pool: crate::buffer::BufferPool,
    ) -> Self {
        Self {
            id: cached.id.clone(),
            pipeline: cached.pipeline.clone(),
            bind_group_layouts: cached.bind_group_layouts.clone(),
            bind_group_cache: cached.bind_group_cache.clone(),
            buffer_bindings: cached.buffer_bindings.clone(),
            output_bindings: cached.output_bindings.clone(),
            execution_plan: cached.execution_plan.clone(),
            device_queue,
            output: cached.output,
            output_word_count: cached.output_word_count,
            workgroup_size: cached.workgroup_size,
            indirect: cached.indirect.clone(),
            trap_tags: cached.trap_tags.clone(),
            persistent_pool,
            staging_pool: cached.staging_pool.clone(),
        }
    }

    /// Pre-compile `program` into a reusable pipeline.
    ///
    /// First-call: performs WGSL lowering, ComputePipeline creation, and
    /// BindGroupLayout caching, then INSERTS the result in `PIPELINE_CACHE`
    /// keyed by the serialized IR + adapter fingerprint.
    ///
    /// Subsequent calls with the same Program on the same adapter skip
    /// the ComputePipeline / BindGroupLayout creation entirely — the cache
    /// returns the same `Arc<wgpu::ComputePipeline>` and the new
    /// `WgpuPipeline` instance just carries fresh metadata (output sizing).
    /// Per-Program metadata varies even when the WGSL doesn't, so it stays
    /// per-instance.
    pub fn compile(program: &Program) -> Result<Arc<Self>, BackendError> {
        Self::compile_with_config(program, &DispatchConfig::default())
    }

    /// Pre-compile `program` into a reusable pipeline using dispatch policy.
    ///
    /// # Errors
    ///
    /// Returns a backend error when lowering, cache access, or pipeline
    /// creation fails.
    pub fn compile_with_config(
        program: &Program,
        config: &DispatchConfig,
    ) -> Result<Arc<Self>, BackendError> {
        let ((device, queue), adapter_info, enabled_features) =
            runtime::init_device().map_err(|error| BackendError::new(error.to_string()))?;
        // Build a fresh pool tied to this call's device+queue. The
        // pool lives as long as the returned pipeline; consumers
        // that want cross-pipeline pool sharing go through
        // `WgpuBackend::acquire` instead (which owns one pool per
        // adapter).
        let pool = crate::buffer::BufferPool::new(device.clone(), queue.clone(), config);
        Self::compile_with_device_queue(
            program,
            config,
            adapter_info,
            enabled_features,
            Arc::new((device, queue)),
            DispatchArena::new(),
            pool,
            Arc::new(runtime::cache::pipeline::LruPipelineCache::new(
                MAX_PIPELINE_CACHE_ENTRIES as u32,
            )),
        )
    }

    /// Pre-compile `program` using the supplied backend-owned device and arena.
    ///
    /// # Errors
    ///
    /// Returns a backend error when lowering, cache access, or pipeline
    /// creation fails.
    pub(crate) fn compile_with_device_queue(
        program: &Program,
        config: &DispatchConfig,
        adapter_info: wgpu::AdapterInfo,
        enabled_features: crate::runtime::device::EnabledFeatures,
        device_queue: Arc<(wgpu::Device, wgpu::Queue)>,
        _dispatch_arena: DispatchArena,
        persistent_pool: crate::buffer::BufferPool,
        pipeline_cache: Arc<runtime::cache::pipeline::LruPipelineCache>,
    ) -> Result<Arc<Self>, BackendError> {
        let compile_program = program;
        // Cache-first: both keys are checked before `execution_plan::plan`
        // and before binding-metadata construction (orchestration sweep 2026-04).
        let early_key = early_pipeline_cache_key(compile_program, &adapter_info, config);
        if let Some(hit) = pipeline_cache.get(&early_key) {
            return Ok(Arc::new(Self::from_cached_artifact(
                hit.as_ref(),
                device_queue,
                persistent_pool,
            )));
        }

        let wgsl =
            load_or_compile_disk_wgsl(compile_program, &adapter_info, config, &enabled_features)?;
        let artifact_key = compiled_pipeline_cache_key(&adapter_info, &wgsl);

        if let Some(hit) = pipeline_cache.get(&artifact_key.hash) {
            pipeline_cache.insert(early_key, Arc::clone(&hit));
            return Ok(Arc::new(Self::from_cached_artifact(
                hit.as_ref(),
                device_queue,
                persistent_pool,
            )));
        }

        let staging_pool = StagingBufferPool::new();
        let trap_tags = naga_emit::trap_tags(compile_program).map_err(|error| {
            BackendError::new(format!(
                "failed to collect wgpu trap tags: {error}. Fix: provide a Program accepted by the trap sidecar lowering pre-pass."
            ))
        })?;
        let validation_options = ValidationOptions::default().with_backend_capabilities(
            crate::capabilities::validation_capabilities(&adapter_info, &enabled_features),
        );
        let execution_plan = Arc::new(
            execution_plan::plan_with_options(compile_program, validation_options).map_err(
                |error| {
                    BackendError::new(format!(
                        "Fix: wgpu pipeline planning rejected the Program: {error}"
                    ))
                },
            )?,
        );
        let output_bindings = output_layouts_from_program(program)?;
        let primary_output = output_bindings.first().ok_or_else(|| {
            BackendError::new(
                "program has no writable output buffer. Fix: declare at least one read-write/output buffer in the vyre Program.",
            )
        })?;
        let output = primary_output.layout;
        // VYRE_NAGA_LOWER audit CRIT-01: dispatch geometry must
        // account for every axis of the workgroup size, not just X.
        // A shader with `@workgroup_size(8, 8, 1)` runs 64 threads
        // per workgroup; dispatching one X-workgroup per 8 output
        // words would launch 64× the intended thread count and
        // write past the output buffer. Store the product so the
        // dispatch-count math downstream divides the right number.
        let effective_wg = config
            .workgroup_override
            .unwrap_or(compile_program.workgroup_size);
        let workgroup_size = effective_wg[0]
            .max(1)
            .saturating_mul(effective_wg[1].max(1))
            .saturating_mul(effective_wg[2].max(1));
        let output_word_count = primary_output.word_count;
        let indirect = find_indirect_dispatch(compile_program)?;
        let public_output_bindings: std::collections::BTreeSet<u32> = output_bindings
            .iter()
            .map(|output| output.binding)
            .collect();

        // Derive binding metadata from the prepared Program's
        // BufferDecl list plus backend-owned sidecars. Going through
        // `naga_emit::prepared_program` is critical: that pre-pass
        // applies BufferAccess auto-inference (ReadWrite buffers
        // never written are downgraded to ReadOnly). The pipeline-
        // layout descriptor and the WGSL shader emission must agree
        // bit-for-bit on access mode; both sides going through the
        // same prepared Program guarantees that. Pre-fix: pipeline.rs
        // used `compile_program.buffers()` directly while the WGSL
        // emitter used `prepared_program(compile_program).buffers()`,
        // and they could diverge on access mode.
        let prepared_for_bindings = naga_emit::prepared_program(compile_program).map_err(|error| {
            BackendError::new(format!(
                "failed to prepare program for binding-metadata construction: {error}. Fix: ensure the Program is accepted by inline_calls + optimize + access auto-inference."
            ))
        })?;
        let mut binding_decls = prepared_for_bindings.buffers().to_vec();
        if !trap_tags.is_empty() {
            binding_decls.push(
                naga_emit::trap_sidecar_decl(compile_program).map_err(|error| {
                    BackendError::new(format!(
                        "failed to reserve wgpu trap sidecar binding: {error}. Fix: leave one storage binding free for backend-owned trap propagation."
                    ))
                })?,
            );
        }
        let buffer_bindings: Arc<[BufferBindingInfo]> = binding_decls
            .iter()
            .filter(|b| b.kind() != vyre::ir::MemoryKind::Shared)
            .map(|b| BufferBindingInfo {
                group: crate::lowering::bind_group_for(b.kind()),
                binding: b.binding(),
                name: Arc::from(b.name()),
                access: b.access(),
                kind: b.kind(),
                hints: b.hints(),
                element: b.element(),
                count: b.count(),
                is_output: public_output_bindings.contains(&b.binding()),
                preserve_input_contents: b.access() == vyre::ir::BufferAccess::ReadWrite
                    && !b.is_output()
                    && b.name() != TRAP_SIDECAR_NAME,
                internal_trap: b.name() == TRAP_SIDECAR_NAME,
            })
            .collect();

        let max_group = buffer_bindings.iter().map(|b| b.group).max().unwrap_or(0);

        // Compile outside any lock so other threads can read the cache.
        let (device, _queue) = &*device_queue;

        // Build explicit bind group layouts from the Program's BufferDecl list.
        // wgpu's auto-derived layout strips bindings that are declared in WGSL
        // but never referenced by the shader body. Primitives that declare a
        // canonical ABI (e.g. the 5-buffer ProgramGraph CSR) may not touch
        // every buffer in every invocation. An explicit layout guarantees the
        // bind group descriptor and pipeline layout agree on binding count.
        let mut bind_group_layouts_vec: Vec<Arc<wgpu::BindGroupLayout>> =
            Vec::with_capacity((max_group + 1) as usize);
        for group_index in 0..=max_group {
            let entries: Vec<wgpu::BindGroupLayoutEntry> = buffer_bindings
                .iter()
                .filter(|b| b.group == group_index)
                .map(|b| {
                    let ty = match b.kind {
                        vyre::ir::MemoryKind::Uniform | vyre::ir::MemoryKind::Push => {
                            wgpu::BindingType::Buffer {
                                ty: wgpu::BufferBindingType::Uniform,
                                has_dynamic_offset: false,
                                min_binding_size: None,
                            }
                        }
                        _ => {
                            // The WGSL emitter (lowering/naga_emit/utils.rs::address_space)
                            // forces StorageAccess::LOAD when the buffer's
                            // MemoryKind == Readonly, regardless of the
                            // BufferAccess flag. The pipeline layout MUST
                            // agree exactly with the emitted shader; otherwise
                            // wgpu's compute_pipeline_descriptor validator
                            // rejects with "Storage class LOAD|STORE doesn't
                            // match the shader Storage LOAD" on every binding
                            // where MemoryKind::Readonly was paired with
                            // BufferAccess::ReadWrite. Align the layout to
                            // the kind-driven access used by the shader.
                            let read_only = matches!(b.kind, vyre::ir::MemoryKind::Readonly)
                                || matches!(
                                    b.access,
                                    vyre::ir::BufferAccess::ReadOnly
                                        | vyre::ir::BufferAccess::Uniform
                                );
                            wgpu::BindingType::Buffer {
                                ty: wgpu::BufferBindingType::Storage { read_only },
                                has_dynamic_offset: false,
                                min_binding_size: None,
                            }
                        }
                    };
                    wgpu::BindGroupLayoutEntry {
                        binding: b.binding,
                        visibility: wgpu::ShaderStages::COMPUTE,
                        ty,
                        count: None,
                    }
                })
                .collect();
            let layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
                label: Some(&format!("vyre P-6 bind group layout {group_index}")),
                entries: &entries,
            });
            bind_group_layouts_vec.push(Arc::new(layout));
        }
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("vyre P-6 pipeline layout"),
            bind_group_layouts: &bind_group_layouts_vec
                .iter()
                .map(|l| l.as_ref())
                .collect::<Vec<_>>(),
            push_constant_ranges: &[],
        });

        let pipeline_cache_handle = create_compiled_pipeline_cache(device, &artifact_key)?;
        runtime::shader::dump_wgsl_if_requested("vyre P-6 cached shader module", &wgsl).map_err(
            |error| {
                BackendError::new(format!(
                    "failed to dump WGSL for compiled pipeline: {error}. Fix: set VYRE_DUMP_WGSL to a writable directory or unset it"
                ))
            },
        )?;
        device.push_error_scope(wgpu::ErrorFilter::Validation);
        let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("vyre P-6 cached shader module"),
            source: wgpu::ShaderSource::Wgsl(wgsl.into()),
        });
        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("vyre P-6 cached pipeline"),
            layout: Some(&pipeline_layout),
            module: &module,
            entry_point: Some("main"),
            compilation_options: wgpu::PipelineCompilationOptions::default(),
            cache: Some(&pipeline_cache_handle.cache),
        });
        match device.poll(wgpu::Maintain::Wait) {
            wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => {}
        }
        if let Some(error) = pollster::block_on(device.pop_error_scope()) {
            return Err(BackendError::KernelCompileFailed {
                backend: "wgpu".to_owned(),
                compiler_message: format!(
                    "cached WGSL pipeline validation failed: {error}. Fix: validate the lowered WGSL, bind-group layout, and adapter limits before compiling."
                ),
            });
        }
        persist_compiled_pipeline_cache(&artifact_key, &pipeline_cache_handle.cache)?;

        let bind_group_layouts: Arc<[Arc<wgpu::BindGroupLayout>]> = bind_group_layouts_vec.into();

        let compiled_artifact = Arc::new(CachedPipelineArtifact {
            id: format!("wgpu:{}", hex_short(&artifact_key.hash)),
            pipeline: Arc::new(pipeline),
            bind_group_layouts,
            bind_group_cache: Arc::new(BindGroupCache::default()),
            execution_plan: execution_plan.clone(),
            output_bindings: output_bindings.clone(),
            buffer_bindings: buffer_bindings.clone(),
            output,
            output_word_count,
            workgroup_size,
            indirect: indirect.clone(),
            trap_tags: trap_tags.clone(),
            staging_pool: staging_pool.clone(),
        });

        // Double-check: another thread may have inserted while we compiled.
        let inserted_arc = pipeline_cache.get(&artifact_key.hash).unwrap_or_else(|| {
            pipeline_cache.insert(artifact_key.hash, Arc::clone(&compiled_artifact));
            Arc::clone(&compiled_artifact)
        });

        // VYRE_NAGA_LOWER CRIT-02: populate the early-key entry so the
        // next compile of the same Program can skip WGSL lowering.
        // Insert rather than entry-API because this map key points at
        // the same artifact as artifact_key.hash — last-writer-wins is
        // fine, both keys reference identical artifacts.
        pipeline_cache.insert(early_key, Arc::clone(&inserted_arc));

        Ok(Arc::new(Self::from_cached_artifact(
            inserted_arc.as_ref(),
            device_queue,
            persistent_pool,
        )))
    }

    /// Dispatch one chunk through this compiled pipeline.
    ///
    /// This is the synchronous primitive used by the host-ingress compatibility
    /// stream; callers that still receive chunks through CPU memory should use
    /// [`crate::engine::streaming::HostIngressStream`]. Canonical VYRE
    /// streaming is the device-resident megakernel queue in `vyre-runtime`.
    ///
    /// # Errors
    ///
    /// Returns a backend error if GPU dispatch or readback fails.
    pub fn push_chunk(
        &self,
        bytes: &[u8],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        // Route through dispatch_borrowed to avoid the owned-Vec copy
        // on the hot streaming path. Callers pass `&[u8]` per chunk;
        // dispatch() would allocate a `Vec<Vec<u8>>` just to wrap it.
        <Self as CompiledPipeline>::dispatch_borrowed(self, &[bytes], config)
    }

    pub(crate) fn output_binding(
        &self,
        binding: u32,
    ) -> Result<&OutputBindingLayout, BackendError> {
        self.output_bindings
            .iter()
            .find(|output| output.binding == binding)
            .ok_or_else(|| {
                BackendError::new(format!(
                    "missing output layout metadata for binding {binding}. Fix: keep output_bindings synchronized with writable BufferDecls during pipeline compilation."
                ))
            })
    }

    /// Substrate-neutral performance and accuracy plan computed for this
    /// compiled program.
    #[must_use]
    pub fn execution_plan(&self) -> &ExecutionPlan {
        &self.execution_plan
    }
}

/// Hex-encode the first 8 bytes of a hash for compact ids.
fn hex_short(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in &bytes[..8] {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn find_indirect_dispatch(program: &Program) -> Result<Option<IndirectDispatch>, BackendError> {
    if !program.has_indirect_dispatch() {
        return Ok(None);
    }
    let mut found = None;
    let mut collector = IndirectDispatchCollector { found: &mut found };
    for node in program.entry() {
        if let ControlFlow::Break(err) = visit_node_preorder(&mut collector, node) {
            return Err(err);
        }
    }
    Ok(found)
}

struct IndirectDispatchCollector<'a> {
    found: &'a mut Option<IndirectDispatch>,
}

impl NodeVisitor for IndirectDispatchCollector<'_> {
    type Break = BackendError;

    fn visit_let(
        &mut self,
        _: &vyre::ir::Node,
        _: &vyre::ir::Ident,
        _: &vyre::ir::Expr,
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_assign(
        &mut self,
        _: &vyre::ir::Node,
        _: &vyre::ir::Ident,
        _: &vyre::ir::Expr,
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_store(
        &mut self,
        _: &vyre::ir::Node,
        _: &vyre::ir::Ident,
        _: &vyre::ir::Expr,
        _: &vyre::ir::Expr,
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_if(
        &mut self,
        _: &vyre::ir::Node,
        _: &vyre::ir::Expr,
        _: &[vyre::ir::Node],
        _: &[vyre::ir::Node],
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_loop(
        &mut self,
        _: &vyre::ir::Node,
        _: &vyre::ir::Ident,
        _: &vyre::ir::Expr,
        _: &vyre::ir::Expr,
        _: &[vyre::ir::Node],
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_indirect_dispatch(
        &mut self,
        _: &vyre::ir::Node,
        count_buffer: &vyre::ir::Ident,
        count_offset: u64,
    ) -> ControlFlow<Self::Break> {
        if count_offset % 4 != 0 {
            return ControlFlow::Break(BackendError::new(format!(
                "indirect dispatch offset {count_offset} is not 4-byte aligned. Fix: use a u32-aligned dispatch tuple."
            )));
        }
        let next = IndirectDispatch {
            count_buffer: count_buffer.to_string(),
            count_offset,
        };
        if self.found.replace(next).is_some() {
            return ControlFlow::Break(BackendError::new(
                "program declares more than one indirect dispatch source. Fix: keep exactly one Node::IndirectDispatch per Program.",
            ));
        }
        Continue(())
    }

    fn visit_async_load(
        &mut self,
        _: &vyre::ir::Node,
        _: &vyre::ir::Ident,
        _: &vyre::ir::Ident,
        _: &vyre::ir::Expr,
        _: &vyre::ir::Expr,
        _: &vyre::ir::Ident,
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_async_store(
        &mut self,
        _: &vyre::ir::Node,
        _: &vyre::ir::Ident,
        _: &vyre::ir::Ident,
        _: &vyre::ir::Expr,
        _: &vyre::ir::Expr,
        _: &vyre::ir::Ident,
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_async_wait(
        &mut self,
        _: &vyre::ir::Node,
        _: &vyre::ir::Ident,
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_trap(
        &mut self,
        _: &vyre::ir::Node,
        _: &vyre::ir::Expr,
        _: &vyre::ir::Ident,
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_resume(
        &mut self,
        _: &vyre::ir::Node,
        _: &vyre::ir::Ident,
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_return(&mut self, _: &vyre::ir::Node) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_barrier(&mut self, _: &vyre::ir::Node) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_block(
        &mut self,
        _: &vyre::ir::Node,
        _: &[vyre::ir::Node],
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_region(
        &mut self,
        _: &vyre::ir::Node,
        _: &vyre::ir::Ident,
        _: &Option<GeneratorRef>,
        _: &[vyre::ir::Node],
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_opaque_node(
        &mut self,
        _: &vyre::ir::Node,
        _: &dyn vyre::ir::NodeExtension,
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }
}

impl CompiledPipeline for WgpuPipeline {
    fn id(&self) -> &str {
        &self.id
    }

    fn dispatch(
        &self,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        let borrowed: SmallVec<[&[u8]; 8]> = inputs.iter().map(Vec::as_slice).collect();
        self.dispatch_borrowed(&borrowed, config)
    }

    fn dispatch_borrowed(
        &self,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        self.enforce_static_output_budget(config)?;
        let deadline = config
            .timeout
            .and_then(|timeout| Instant::now().checked_add(timeout));
        let workgroup_count = if let Some(grid) = config.grid_override {
            grid
        } else {
            let count = self
                .output_word_count
                .div_ceil(self.workgroup_size as usize)
                .max(1)
                .try_into()
                .unwrap_or(u32::MAX);
            [count, 1, 1]
        };

        let (input_handles, mut output_handles) = self.legacy_handles_from_inputs(inputs)?;
        // Caller may opt into a fixpoint composition: run the same
        // program K times back-to-back on the SAME persistent input
        // and output handles, so any ReadWrite intermediate buffers
        // accumulate state across iterations. This is what lets the
        // surgec rule chain converge multi-hop reachability — a
        // single dispatch only finishes one BFS step's worth of work
        // because cross-workgroup synchronization isn't possible
        // inside one launch. After each iteration, sample the
        // primary output buffer; stop early when it stops changing.
        let max_iters = config.fixpoint_iterations.unwrap_or(1).max(1) as usize;
        for _ in 0..max_iters {
            self.dispatch_persistent(&input_handles, &mut output_handles, None, workgroup_count)?;
        }
        let (device, queue) = &*self.device_queue;
        self.raise_if_trapped(&input_handles, device, queue, deadline)?;
        let mut outputs = Vec::with_capacity(output_handles.len());
        for (handle, output) in output_handles.iter().zip(self.output_bindings.iter()) {
            let mut bytes = Vec::with_capacity(usize::try_from(handle.byte_len()).unwrap_or(0));
            handle.readback_until(
                device,
                Some(&self.staging_pool),
                queue,
                &mut bytes,
                deadline,
            )?;
            let end = output
                .layout
                .trim_start
                .saturating_add(output.layout.read_size);
            if end > bytes.len() {
                return Err(BackendError::new(format!(
                    "persistent legacy readback slice for `{}` is out of bounds. Fix: verify OutputLayout against the GPU output allocation.",
                    output.name
                )));
            }
            bytes.truncate(end);
            if output.layout.trim_start > 0 {
                bytes.drain(0..output.layout.trim_start);
            }
            outputs.push(bytes);
        }
        enforce_actual_output_budget(config, &outputs)?;
        Ok(outputs)
    }
}

impl WgpuPipeline {
    fn raise_if_trapped(
        &self,
        input_handles: &[crate::buffer::GpuBufferHandle],
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        deadline: Option<Instant>,
    ) -> Result<(), BackendError> {
        let Some((input_index, _)) = self
            .buffer_bindings
            .iter()
            .filter(|info| info.kind != vyre::ir::MemoryKind::Shared && !info.is_output)
            .enumerate()
            .find(|(_, info)| info.internal_trap)
        else {
            return Ok(());
        };
        let Some(handle) = input_handles.get(input_index) else {
            return Err(BackendError::new(
                "internal wgpu trap buffer was not allocated. Fix: keep trap buffer binding metadata synchronized with legacy input handle allocation.",
            ));
        };
        let mut bytes = Vec::with_capacity((TRAP_SIDECAR_WORDS as usize) * 4);
        handle.readback_prefix_until(
            device,
            Some(&self.staging_pool),
            queue,
            u64::from(TRAP_SIDECAR_WORDS) * 4,
            &mut bytes,
            deadline,
        )?;
        trap_error_from_sidecar(&bytes, &self.trap_tags).map_or(Ok(()), Err)
    }

    fn enforce_static_output_budget(&self, config: &DispatchConfig) -> Result<(), BackendError> {
        let Some(limit) = config.max_output_bytes else {
            return Ok(());
        };
        let planned = self.execution_plan.strategy.readback.visible_bytes();
        let planned = usize::try_from(planned).map_err(|source| {
            BackendError::new(format!(
                "planned readback size cannot fit usize: {source}. Fix: split the Program output before dispatch."
            ))
        })?;
        if planned > limit {
            return Err(BackendError::new(format!(
                "planned readback size {planned} exceeds DispatchConfig.max_output_bytes {limit}. Fix: narrow BufferDecl::output_byte_range or raise max_output_bytes."
            )));
        }
        Ok(())
    }
}

fn enforce_actual_output_budget(
    config: &DispatchConfig,
    outputs: &[Vec<u8>],
) -> Result<(), BackendError> {
    let Some(limit) = config.max_output_bytes else {
        return Ok(());
    };
    let actual = outputs.iter().try_fold(0usize, |sum, output| {
        sum.checked_add(output.len()).ok_or_else(|| {
            BackendError::new(
                "actual readback size overflows usize. Fix: split the Program output before dispatch.",
            )
        })
    })?;
    if actual > limit {
        return Err(BackendError::new(format!(
            "actual readback size {actual} exceeds DispatchConfig.max_output_bytes {limit}. Fix: narrow BufferDecl::output_byte_range or raise max_output_bytes."
        )));
    }
    Ok(())
}

pub(crate) fn trap_error_from_sidecar(bytes: &[u8], trap_tags: &[TrapTag]) -> Option<BackendError> {
    let required_len = (TRAP_SIDECAR_WORDS as usize) * 4;
    if bytes.len() < required_len {
        return Some(BackendError::new(format!(
            "internal wgpu trap readback returned {} bytes but {required_len} bytes are required. Fix: allocate the trap sidecar as {TRAP_SIDECAR_WORDS} u32 words.",
            bytes.len()
        )));
    }
    let flag = u32::from_le_bytes(bytes[0..4].try_into().expect("slice length checked"));
    if flag == 0 {
        return None;
    }
    let address = u32::from_le_bytes(bytes[4..8].try_into().expect("slice length checked"));
    let tag_code = u32::from_le_bytes(bytes[8..12].try_into().expect("slice length checked"));
    let lane = u32::from_le_bytes(bytes[12..16].try_into().expect("slice length checked"));
    let tag = trap_tags
        .iter()
        .find(|tag| tag.code == tag_code)
        .map(|tag| tag.tag.as_ref())
        .unwrap_or("unknown Node::Trap tag code");
    Some(BackendError::new(format!(
        "wgpu dispatch trapped: address={address}, tag_code={tag_code}, lane={lane}, tag=`{tag}`."
    )))
}

/// Output readback layout derived from a program's declared output range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputLayout {
    /// Full output buffer byte size allocated on the GPU.
    pub full_size: usize,
    /// Consumer-visible byte count returned from dispatch.
    pub read_size: usize,
    /// Aligned source offset copied from the GPU output buffer.
    pub copy_offset: usize,
    /// Aligned staging-buffer byte size.
    pub copy_size: usize,
    /// Offset within the staging buffer where the requested range starts.
    pub trim_start: usize,
}

/// Derive output readback layout for a program.
///
/// # Errors
///
/// Returns a backend error when the program has no output buffer or declares
/// an out-of-bounds output byte range.
pub fn output_layout_from_program(program: &Program) -> Result<OutputLayout, BackendError> {
    output_layouts_from_program(program)?
        .first()
        .map(|output| output.layout)
        .ok_or_else(|| {
            BackendError::new(
                "program has no output buffer. Fix: declare exactly one output buffer in the vyre Program.",
            )
        })
}

pub(crate) fn output_layouts_from_program(
    program: &Program,
) -> Result<Arc<[OutputBindingLayout]>, BackendError> {
    let outputs: Result<Vec<_>, _> = program
        .output_buffer_indices()
        .iter()
        .map(|&index| {
            let output = program.buffers().get(index as usize).ok_or_else(|| {
                BackendError::new(format!(
                    "output buffer index {index} is out of bounds. Fix: rebuild the Program so writable buffer metadata stays consistent."
                ))
            })?;
            output_binding_layout(output)
        })
        .collect();
    let outputs = outputs?;
    if outputs.is_empty() {
        return Err(BackendError::new(
            "program has no output buffer. Fix: declare at least one writable buffer in the vyre Program.",
        ));
    }
    Ok(outputs.into())
}

fn output_binding_layout(
    output: &vyre::ir::BufferDecl,
) -> Result<OutputBindingLayout, BackendError> {
    let count = usize::try_from(output.count()).map_err(|_| {
        BackendError::new(
            "program output element count exceeds usize. Fix: split the dispatch into smaller output buffers.",
        )
    })?;
    let element_size = element_size_bytes(output.element())?;
    let full_size = count.checked_mul(element_size).ok_or_else(|| {
        BackendError::new(
            "program output byte size overflows usize. Fix: split the dispatch into smaller output buffers.",
        )
    })?;
    let layout = output_layout(output, full_size)?;
    let word_count = full_size
        .checked_add(3)
        .and_then(|n| n.checked_div(4))
        .unwrap_or(full_size)
        .max(1);
    Ok(OutputBindingLayout {
        binding: output.binding(),
        name: Arc::from(output.name()),
        layout,
        word_count,
    })
}

pub(crate) fn output_layout(
    output: &vyre::ir::BufferDecl,
    full_size: usize,
) -> Result<OutputLayout, BackendError> {
    let range = output.output_byte_range().unwrap_or(0..full_size);
    if range.start > range.end || range.end > full_size {
        return Err(BackendError::new(format!(
            "output byte range {:?} is outside output buffer size {full_size}. Fix: declare a range within the output buffer.",
            range
        )));
    }
    let copy_offset = range.start & !3;
    let copy_end = range.end.next_multiple_of(4).min(full_size.max(4));
    let copy_size = (copy_end.saturating_sub(copy_offset)).max(4);
    Ok(OutputLayout {
        full_size,
        read_size: range.end - range.start,
        copy_offset,
        copy_size,
        trim_start: range.start - copy_offset,
    })
}

pub(crate) fn element_size_bytes(data_type: vyre::ir::DataType) -> Result<usize, BackendError> {
    data_type.size_bytes().ok_or_else(|| {
        BackendError::new(
            "output buffer element type has no fixed scalar element size. Fix: validate the Program and flatten variable-size outputs before wgpu pipeline compilation.",
        )
    })
}

#[cfg(test)]
mod tests;
