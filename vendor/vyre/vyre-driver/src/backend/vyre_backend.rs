//! The frozen `VyreBackend` contract.

use std::sync::Arc;
use std::time::Duration;

use vyre_foundation::ir::Program;

use crate::backend::{private, BackendError, CompiledPipeline, PendingDispatch};

#[derive(Clone, Debug, Eq, PartialEq)]
/// A GPU-resident or host-side resource used as an input to a Program.
pub enum Resource {
    /// Host-side byte slice. Replicated to the GPU on each dispatch.
    Borrowed(Vec<u8>),
    /// GPU-resident buffer handle. Zero-copy — no host transfer occurs.
    Resident(u64), // Stable handle ID
}

impl Default for Resource {
    fn default() -> Self {
        Resource::Borrowed(Vec::new())
    }
}

impl From<Vec<u8>> for Resource {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Borrowed(bytes)
    }
}

/// Immutable execution policy supplied by the caller before dispatch.
///
/// `DispatchConfig` is an additive, non-exhaustive struct so that new backend
/// options (conformance profiles, adapter hints, etc.) can be added without
/// breaking the frozen `VyreBackend::dispatch` signature. Backends must treat
/// every field as read-only policy and must not assume the presence of any
/// particular option.
///
/// # Examples
///
/// ```
/// use vyre::DispatchConfig;
///
/// // DispatchConfig is `#[non_exhaustive]`; construct it through
/// // `default()` and overwrite the fields you want to change.
/// let mut config = DispatchConfig::default();
/// config.profile = Some("stress".to_string());
/// config.ulp_budget = None;
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DispatchConfig {
    /// Optional stable profile identifier such as `default`, `stress`, or a
    /// backend-defined conformance mode.
    pub profile: Option<String>,
    /// Optional maximum ULP error budget for approximate transcendental lowering.
    ///
    /// `None` and `Some(0)` require the strict WGSL intrinsic path. A positive
    /// budget allows backends to select fast approximate intrinsic wrappers only
    /// when the wrapper contract is bounded by the supplied ULP ceiling.
    pub ulp_budget: Option<u8>,
    /// Optional timeout for the dispatch.
    pub timeout: Option<Duration>,
    /// Optional label for the dispatch (for debugging/profiling).
    pub label: Option<String>,
    /// Optional maximum output byte limit.
    pub max_output_bytes: Option<usize>,
    /// Optional workgroup size override.
    ///
    /// When `Some`, the backend uses the supplied `[x, y, z]` workgroup size
    /// instead of the one declared on the [`Program`]. This lets callers tune
    /// workgroup sizing at dispatch time without cloning the [`Program`] metadata
    /// struct. When `None` (the default), the backend falls back to
    /// `program.workgroup_size`.
    pub workgroup_override: Option<[u32; 3]>,
    /// Optional grid size override (number of workgroups).
    ///
    /// When set, the backend launches the supplied workgroup count instead of
    /// the one inferred from the program's output buffer size.
    /// This is required for megakernels where the work queue length is
    /// managed through storage buffers rather than the primary output slot.
    pub grid_override: Option<[u32; 3]>,
    /// Maximum back-to-back dispatch iterations the backend should run on
    /// the same persistent input/output handles before reading back the
    /// final outputs. `None` or `Some(1)` means single-shot dispatch; any
    /// `Some(n)` with `n >= 2` reuses the GPU-resident buffers between
    /// iterations so taint-style fixpoint composition (`csr_forward_traverse`
    /// plus a bitset accumulator) can converge across N hops without
    /// cross-workgroup synchronization. The backend MUST stop early when none
    /// of the read-write buffers change between iterations.
    pub fixpoint_iterations: Option<u32>,
}

impl DispatchConfig {
    /// Construct a `DispatchConfig` from explicit fields in one call.
    /// Complement to `DispatchConfig::default()` for external crates
    /// that want all optional fields set up front (V7-EXT-024).
    #[must_use]
    pub fn new(
        profile: Option<String>,
        ulp_budget: Option<u8>,
        timeout: Option<Duration>,
        label: Option<String>,
    ) -> Self {
        Self {
            profile,
            ulp_budget,
            timeout,
            label,
            max_output_bytes: None,
            workgroup_override: None,
            grid_override: None,
            fixpoint_iterations: None,
        }
    }
}

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

    // `fn dispatch_wgsl(...)` was removed after the conform legacy
    // probes migrated to vyre IR. Raw WGSL is a wgpu-implementation
    // detail, not part of the substrate-neutral `VyreBackend`
    // contract; consumers that still need to run a raw WGSL string
    // call `WgpuBackend::dispatch_wgsl` on the concrete wgpu backend
    // directly.

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
        let owned: Vec<Vec<u8>> = inputs.iter().map(|input| (*input).to_vec()).collect();
        self.dispatch(program, &owned, config)
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
    /// `docs/audits/ROADMAP_PERFORMANCE.md`: "compile WGSL + pipeline +
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

    /// Non-blocking dispatch primitive.
    ///
    /// Returns a [`PendingDispatch`] handle immediately; the caller
    /// polls via [`PendingDispatch::is_ready`] and consumes the result
    /// via [`PendingDispatch::await_result`]. Backends that genuinely
    /// pipeline dispatches (wgpu's `map_async`, CUDA's
    /// `cuStreamSynchronize`, Metal's `MTLCommandBuffer` completion
    /// handlers) override this so N concurrent dispatches do not
    /// serialize on the host.
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

    // ---------------------------------------------------------------
    // Capability queries (all default to conservative "no" / minimal).
    //
    // These are the v0.6 terminal capability surface. A backend added in
    // 0.7 (CUDA, Metal, photonic, CPU-SIMD, distributed) implements this
    // trait by default-inheriting every capability below and OVERRIDING
    // only the ones where it is more capable than the conservative floor.
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
    /// knows it (e.g. `wgpu::Limits::min_subgroup_size`). Returning
    /// `None` tells the dispatch planner the backend can't report a
    /// subgroup width — the planner falls back to `max_workgroup_size`
    /// for its sizing heuristic.
    ///
    /// I.6 — adaptive workgroup sizing reads this capability to pick
    /// a workgroup multiple of the subgroup so threads don't straddle
    /// warps. Desktop NVIDIA is 32, mobile 16, server AMD/Intel 64.
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
