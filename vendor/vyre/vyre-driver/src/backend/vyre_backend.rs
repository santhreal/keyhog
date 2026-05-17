//! The frozen `VyreBackend` contract.

use std::sync::Arc;

use smallvec::SmallVec;
use vyre_foundation::ir::Program;

use crate::backend::{
    private, BackendError, CompiledPipeline, DispatchConfig, OutputBuffers, PendingDispatch,
    Resource, TimedDispatchResult,
};

/// The frozen contract between vyre and every execution backend.
///
/// A backend is a pure function from a validated `Program` and input buffers
/// to output buffers. Implementations must be `Send + Sync`, deterministic
/// for identical inputs, and byte-identical to the CPU reference on success.
/// This trait is the keystone of the vyre abstraction thesis: frontends do
/// not know which backend runs their IR, and backends do not know which
/// frontend produced it.
///
/// # Examples
///
pub trait VyreBackend: private::Sealed + Send + Sync {
    /// Stable backend identifier used for logging, certificates, and adapter selection.
    ///
    /// The identifier must be unique among all backends linked into the
    /// current process. Conformance reports include this string so that
    /// consumers know exactly which implementation was certified.
    fn id(&self) -> &'static str;

    /// Backend implementation version string used for certificates and
    /// regression tracking.
    ///
    /// The default returns `"unspecified"`. Concrete backends should
    /// override this with their crate version (e.g. `"0.4.0"`) so that
    /// certificates can detect backend upgrades that may require re-cert.
    fn version(&self) -> &'static str {
        "unspecified"
    }

    /// Operation ids this backend can execute without further lowering.
    fn supported_ops(&self) -> &std::collections::HashSet<vyre_foundation::ir::OpId> {
        use crate::backend::validation::default_supported_ops;
        default_supported_ops()
    }

    // Raw backend shader text is a concrete-driver implementation
    // detail, not part of the substrate-neutral `VyreBackend`
    // contract.

    /// Executes the program with the given input buffers and returns the output buffers.
    ///
    /// On success the returned bytes must match the pure-Rust reference
    /// implementation bit-for-bit. On failure the backend must return a
    /// [`BackendError`] whose message contains an actionable `Fix: ` hint.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use vyre::{Program, VyreBackend, DispatchConfig};
    ///
    /// # fn example(backend: &dyn VyreBackend, program: &Program) -> Result<Vec<Vec<u8>>, vyre::BackendError> {
    /// let inputs = vec![vec![1u8, 2, 3]];
    /// let config = DispatchConfig::default();
    /// backend.dispatch(program, &inputs, &config)
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the backend cannot complete dispatch.
    /// The error message always includes a `Fix: ` remediation section.
    fn dispatch(
        &self,
        program: &Program,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError>;

    /// Executes the program with borrowed input buffers.
    ///
    /// Backends may override this method to avoid staging borrowed bytes into
    /// owned `Vec<u8>` buffers. The default is non-breaking: it performs one
    /// owned vector allocation for the call and delegates to
    /// [`VyreBackend::dispatch`].
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the backend cannot complete dispatch.
    fn dispatch_borrowed(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        let owned: SmallVec<[Vec<u8>; 8]> = inputs.iter().map(|input| (*input).to_vec()).collect();
        self.dispatch(program, &owned, config)
    }

    /// Executes a borrowed-input dispatch and returns backend-owned timing.
    ///
    /// The default records host wall time and delegates to
    /// [`VyreBackend::dispatch_borrowed`]. Device-specific backends override
    /// this only inside their driver crates so benchmark crates never import
    /// vendor APIs directly.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the backend cannot complete dispatch.
    fn dispatch_borrowed_timed(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<TimedDispatchResult, BackendError> {
        let started = std::time::Instant::now();
        let outputs = self.dispatch_borrowed(program, inputs, config)?;
        Ok(TimedDispatchResult {
            outputs,
            wall_ns: started.elapsed().as_nanos() as u64,
            device_ns: None,
            enqueue_ns: None,
            wait_ns: None,
        })
    }

    /// Executes the program with borrowed input buffers and writes outputs into
    /// caller-owned storage.
    ///
    /// Backends may override this method to reuse output buffers across
    /// dispatches. The default preserves the existing dispatch contract and
    /// moves the returned vectors into `outputs`.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the backend cannot complete dispatch.
    fn dispatch_borrowed_into(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
        outputs: &mut OutputBuffers,
    ) -> Result<(), BackendError> {
        let result = self.dispatch_borrowed(program, inputs, config)?;
        outputs.clear();
        outputs.extend(result);
        Ok(())
    }

    /// Allocate a backend-resident buffer and return a stable resource handle.
    ///
    /// Backends that support resident resources override this method so callers
    /// can keep hot inputs on the device without importing a concrete driver
    /// crate. The returned [`Resource`] is only meaningful to the backend that
    /// produced it.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the backend cannot allocate a resident
    /// resource of the requested size.
    fn allocate_resident(&self, _byte_len: usize) -> Result<Resource, BackendError> {
        Err(BackendError::UnsupportedFeature {
            name: "resident buffer allocation".to_string(),
            backend: self.id().to_string(),
        })
    }

    /// Upload bytes into a backend-resident resource.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the resource is not owned by this backend
    /// or the byte length does not match the resident allocation.
    fn upload_resident(&self, _resource: &Resource, _bytes: &[u8]) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedFeature {
            name: "resident buffer upload".to_string(),
            backend: self.id().to_string(),
        })
    }

    /// Free a backend-resident resource previously returned by
    /// [`VyreBackend::allocate_resident`].
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the resource is unknown or still in use.
    fn free_resident(&self, _resource: Resource) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedFeature {
            name: "resident buffer free".to_string(),
            backend: self.id().to_string(),
        })
    }

    /// Dispatch using backend-resident resources and return backend-owned
    /// timing.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the backend does not support resident
    /// dispatch or any resource is invalid for the program.
    fn dispatch_resident_timed(
        &self,
        _program: &Program,
        _resources: &[Resource],
        _config: &DispatchConfig,
    ) -> Result<TimedDispatchResult, BackendError> {
        Err(BackendError::UnsupportedFeature {
            name: "resident timed dispatch".to_string(),
            backend: self.id().to_string(),
        })
    }

    /// Optional pre-compilation hook for the pipeline-mode API.
    ///
    /// Default returns `Ok(None)` — the framework wraps in a passthrough
    /// pipeline whose `dispatch` calls back into [`VyreBackend::dispatch`]
    /// every time. Backends that genuinely cache compiled state (compute
    /// pipeline, bind-group layout, lowered shader text) override this and
    /// return `Ok(Some(...))` so repeated dispatches skip the compilation
    /// overhead.
    ///
    /// The returned pipeline MUST be bit-identical to repeated
    /// `dispatch(program, inputs, config)` for the program it was compiled
    /// from. The cache key is the backend's responsibility — the framework
    /// does not deduplicate compile calls.
    ///
    /// Implementing this method is the P-6 contract from
    /// `docs/audits/ROADMAP_PERFORMANCE.md`: "compile target-text + pipeline +
    /// bind-group-layout once; dispatch repeatedly with different inputs."
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the backend cannot complete the
    /// pre-compilation. Callers should treat this as fatal for the program
    /// (the program will not dispatch successfully via any path).
    fn compile_native(
        &self,
        _program: &Program,
        _config: &DispatchConfig,
    ) -> Result<Option<Arc<dyn CompiledPipeline>>, BackendError> {
        Ok(None)
    }

    /// Optional pre-compilation hook for callers that already own a shared
    /// program allocation.
    ///
    /// Backends that store the program inside the compiled pipeline should
    /// override this method and keep the supplied [`Arc<Program>`] instead of
    /// cloning the IR. The default preserves the older borrowed-program hook
    /// for backends that only inspect the program while compiling.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when backend-native compilation fails.
    fn compile_native_shared(
        &self,
        program: Arc<Program>,
        config: &DispatchConfig,
    ) -> Result<Option<Arc<dyn CompiledPipeline>>, BackendError> {
        self.compile_native(&program, config)
    }

    /// Optional compiled-pipeline cache counters for compile telemetry.
    ///
    /// Return `None` unless the backend can report real cache hits and misses.
    fn pipeline_cache_snapshot(&self) -> Option<crate::pipeline::PipelineCacheSnapshot> {
        None
    }

    /// Optional backend-specific numeric telemetry for release evidence.
    ///
    /// Return an empty vector unless the backend can report real counters.
    /// Metric names must be stable ASCII identifiers suitable for JSON and
    /// Prometheus-style export.
    fn backend_metric_snapshot(&self) -> Vec<(&'static str, u64)> {
        Vec::new()
    }

    /// Non-blocking dispatch primitive.
    ///
    /// Returns a [`PendingDispatch`] handle immediately; the caller
    /// polls via [`PendingDispatch::is_ready`] and consumes the result
    /// via [`PendingDispatch::await_result`]. Backends that genuinely
    /// pipeline dispatches override this so N concurrent dispatches
    /// do not serialize on the host.
    ///
    /// Default: run the synchronous [`VyreBackend::dispatch`] path and
    /// wrap the result in a trivially-ready handle. This keeps every
    /// backend useful from the async API without forcing an async
    /// rewrite.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if the dispatch cannot start. Errors
    /// that surface only during GPU execution come back through
    /// [`PendingDispatch::await_result`], not from this call.
    fn dispatch_async(
        &self,
        program: &Program,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Box<dyn PendingDispatch>, BackendError> {
        let outputs = self.dispatch(program, inputs, config)?;
        Ok(Box::new(crate::backend::pending_dispatch::ReadyPending {
            outputs,
        }))
    }

    /// Non-blocking dispatch with borrowed input buffers.
    ///
    /// Backends that record GPU commands synchronously before returning can
    /// override this to avoid cloning input buffers just to create a pending
    /// handle. The returned [`PendingDispatch`] must not borrow from `inputs`.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if the dispatch cannot start.
    fn dispatch_borrowed_async(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Box<dyn PendingDispatch>, BackendError> {
        let outputs = self.dispatch_borrowed(program, inputs, config)?;
        Ok(Box::new(crate::backend::pending_dispatch::ReadyPending {
            outputs,
        }))
    }

    // ---------------------------------------------------------------
    // Capability queries (all default to conservative "no" / minimal).
    //
    // These are the stable capability surface. Additional backends implement
    // this trait by default-inheriting every capability below and OVERRIDING
    // only the ones where they are more capable than the conservative floor.
    // This means adding a backend is strictly additive — no existing
    // backend impl has to change when a new capability query is added.
    //
    // Backends MUST report HONESTLY. Returning `true` from a capability
    // query is a promise the lowering path emits the corresponding
    // intrinsic and the adapter supports it. "Supported but broken" is a
    // LAW 9 evasion (see CLAUDE.md). If the feature bit is set on the
    // device but the lowering emits scalar fallback, the answer is
    // `false` until the lowering catches up.
    // ---------------------------------------------------------------

    /// Whether this backend's lowering path emits subgroup / wave
    /// intrinsics AND the current adapter exposes them.
    ///
    /// Default: `false` (conservative — assumes the scalar fallback).
    #[must_use]
    fn supports_subgroup_ops(&self) -> bool {
        false
    }

    /// Whether this backend lowers IEEE 754 binary16 (`DataType::F16`)
    /// natively rather than emulating through `f32`.
    ///
    /// Default: `false`.
    #[must_use]
    fn supports_f16(&self) -> bool {
        false
    }

    /// Whether this backend lowers bfloat16 (`DataType::BF16`) natively.
    ///
    /// Default: `false`.
    #[must_use]
    fn supports_bf16(&self) -> bool {
        false
    }

    /// Whether this backend emits tensor-core / matrix-engine intrinsics
    /// for supported tensor shapes.
    ///
    /// Default: `false`.
    #[must_use]
    fn supports_tensor_cores(&self) -> bool {
        false
    }

    /// Whether this backend overlaps copies and compute via independent
    /// queues or async engines.
    ///
    /// Default: `false` (host serializes copy ↔ compute).
    #[must_use]
    fn supports_async_compute(&self) -> bool {
        false
    }

    /// Whether this backend supports indirect dispatch
    /// (`Node::IndirectDispatch`).
    ///
    /// Default: `false`.
    #[must_use]
    fn supports_indirect_dispatch(&self) -> bool {
        false
    }

    /// Whether this backend supports speculative dispatch — a fused
    /// prefilter + confirmer kernel with commit-gated output and a
    /// counter tail read back by the host.
    ///
    /// Default: `false`.
    #[must_use]
    fn supports_speculation(&self) -> bool {
        false
    }

    /// Whether this backend supports device-side persistent-thread
    /// dispatch (a long-running kernel that polls a work queue).
    ///
    /// Default: `false`.
    #[must_use]
    fn supports_persistent_thread_dispatch(&self) -> bool {
        false
    }

    /// Whether this backend can satisfy `Node::Barrier { ordering:
    /// MemoryOrdering::GridSync }` inside a single dispatch — i.e.
    /// every thread in the entire grid waits at the barrier and
    /// every prior write is globally visible afterwards. Backends
    /// that lack a native grid barrier (workgroup-only fences) must
    /// return `false`; the runtime will lower a `GridSync` barrier
    /// to a kernel split that re-dispatches with the same buffers.
    ///
    /// Backends with cooperative whole-grid launch support can return
    /// `true`; backends limited to workgroup-local synchronization return
    /// `false` until the target exposes a compatible grid-barrier primitive.
    ///
    /// Default: `false`.
    #[must_use]
    fn supports_grid_sync(&self) -> bool {
        false
    }

    /// Whether this backend partitions a program across more than one
    /// physical device / node.
    ///
    /// Default: `false` (single-device execution).
    #[must_use]
    fn is_distributed(&self) -> bool {
        false
    }

    /// Maximum supported workgroup size per axis `[x, y, z]`.
    ///
    /// Default: `[1, 1, 1]` (scalar dispatch — a backend that has not
    /// reported a real limit cannot be trusted to execute parallel
    /// workgroups).
    #[must_use]
    fn max_workgroup_size(&self) -> [u32; 3] {
        [1, 1, 1]
    }

    /// Maximum number of compute workgroups the backend can launch in one
    /// dispatch dimension.
    ///
    /// Default: `1`, which is safe for scalar/reference backends but must be
    /// overridden by real GPU backends so schedulers do not under-launch.
    #[must_use]
    fn max_compute_workgroups_per_dimension(&self) -> u32 {
        1
    }

    /// Maximum total invocations allowed in a single workgroup.
    ///
    /// Default derives from [`max_workgroup_size`](Self::max_workgroup_size)
    /// and clamps overflow to `u32::MAX`.
    #[must_use]
    fn max_compute_invocations_per_workgroup(&self) -> u32 {
        let [x, y, z] = self.max_workgroup_size();
        x.saturating_mul(y).saturating_mul(z)
    }

    /// Native subgroup size for the backing device when the backend
    /// knows it. Returning
    /// `None` tells the dispatch planner the backend can't report a
    /// subgroup width — the planner falls back to `max_workgroup_size`
    /// for its sizing heuristic.
    ///
    /// I.6 — adaptive workgroup sizing reads this capability to pick
    /// a workgroup multiple of the subgroup so threads don't straddle
    /// subgroups. Typical devices expose 16, 32, or 64 lanes.
    #[must_use]
    fn subgroup_size(&self) -> Option<u32> {
        None
    }

    /// Maximum size in bytes of a single storage buffer the backend
    /// accepts. `0` means the backend has not reported a limit, not
    /// "unlimited".
    ///
    /// Default: `0`.
    #[must_use]
    fn max_storage_buffer_bytes(&self) -> u64 {
        0
    }

    /// Unified backend-neutral device profile.
    ///
    /// Shared planner code should prefer this single profile over reading
    /// individual capability methods one by one. Concrete backends may
    /// override it when they can report richer device facts such as shared
    /// memory size or native lowering-strategy features.
    #[must_use]
    fn device_profile(&self) -> crate::DeviceProfile {
        let max_workgroup_size = self.max_workgroup_size();
        crate::DeviceProfile {
            backend: self.id(),
            supports_subgroup_ops: self.supports_subgroup_ops(),
            supports_indirect_dispatch: self.supports_indirect_dispatch(),
            supports_specialization_constants: false,
            supports_f16: self.supports_f16(),
            supports_bf16: self.supports_bf16(),
            supports_trap_propagation: false,
            supports_tensor_cores: self.supports_tensor_cores(),
            has_mul_high: false,
            has_dual_issue_fp32_int32: false,
            has_subgroup_shuffle: self.supports_subgroup_ops(),
            has_shared_memory: false,
            max_native_int_width: 32,
            max_workgroup_size,
            max_invocations_per_workgroup: self.max_compute_invocations_per_workgroup(),
            max_shared_memory_bytes: 0,
            max_storage_buffer_binding_size: self.max_storage_buffer_bytes(),
            subgroup_size: self.subgroup_size().unwrap_or(0),
            compute_units: 0,
            regs_per_thread_max: 0,
            l1_cache_bytes: 0,
            l2_cache_bytes: 0,
            mem_bw_gbps: 0,
            ideal_unroll_depth: 0,
            ideal_vector_pack_bits: 0,
            ideal_workgroup_tile: [0, 0, 0],
            shared_memory_bank_count: 0,
            shared_memory_bank_width_bytes: 0,
        }
    }

    // ---------------------------------------------------------------
    // Lifecycle hooks (defaulted, override as needed).
    //
    // These let a backend warm caches, flush pending work, recover from
    // device loss, or tear down cleanly. Every hook defaults to a
    // no-op-or-structured-error, so existing impls do not have to add
    // any code.
    // ---------------------------------------------------------------

    /// Pre-dispatch warmup. Called before the first dispatch on a new
    /// program so the backend can warm caches, compile ahead-of-time, or
    /// acquire a device handle without paying that cost on the hot path.
    ///
    /// Default: no-op `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if warmup cannot complete.
    fn prepare(&self) -> Result<(), BackendError> {
        Ok(())
    }

    /// Flush any queued work to the device and wait for it to complete.
    ///
    /// Useful before tearing down a context or before reading back data
    /// that was produced by the last asynchronous dispatch.
    ///
    /// Default: no-op `Ok(())` — backends that do not queue work
    /// implicitly satisfy flush.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] on device failure.
    fn flush(&self) -> Result<(), BackendError> {
        Ok(())
    }

    /// Release device resources held by this backend. After `shutdown`
    /// returns the backend is in an unspecified state and may not be
    /// used for further dispatches.
    ///
    /// Default: no-op `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] on device failure during teardown.
    fn shutdown(&self) -> Result<(), BackendError> {
        Ok(())
    }

    /// Probe whether the underlying device has been lost since the last
    /// successful dispatch.
    ///
    /// Default: `false` (assume healthy — backends that have no
    /// device-loss story do not need to probe).
    #[must_use]
    fn device_lost(&self) -> bool {
        false
    }

    /// Attempt to recover from device loss by reacquiring the underlying
    /// device and invalidating pipeline caches.
    ///
    /// Default: returns an `UnsupportedFeature` error — recovery must be
    /// opt-in, because a backend that silently re-acquires without
    /// notifying the caller is a correctness hazard.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::UnsupportedFeature`] by default. Backends
    /// that implement recovery return any error encountered during
    /// re-acquisition.
    fn try_recover(&self) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedFeature {
            name: "device recovery".to_string(),
            backend: self.id().to_string(),
        })
    }
}
