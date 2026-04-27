pub trait VyreBackend: Send + Sync {
/// Stable backend identifier used for logging, certificates, and adapter selection.
///
/// The identifier must be unique among all backends linked into the
/// current process. Conformance reports include this string so that
/// consumers know exactly which implementation was certified.
///
/// # Examples
///
/// ```
/// use vyre::{VyreBackend, DispatchConfig, BackendError, Program};
///
/// struct Stub;
/// impl VyreBackend for Stub {
///     fn id(&self) -> &'static str { "stub" }
///     fn dispatch(&self, _: &Program, _: &[Vec<u8>], _: &DispatchConfig) -> Result<Vec<Vec<u8>>, BackendError> {
///         Ok(vec![])
///     }
/// }
///
/// assert_eq!(Stub.id(), "stub");
/// ```
fn id(&self) -> &'static str;
/// Backend implementation version string used for certificates and
/// regression tracking.
///
/// The default returns `"unspecified"`. Concrete backends should
/// override this with their crate version (e.g. `"0.4.0"`) so that
/// certificates can detect backend upgrades that may require re-cert.
///
/// # Examples
///
/// ```
/// use vyre::VyreBackend;
///
/// struct Stub;
/// impl VyreBackend for Stub {
///     fn id(&self) -> &'static str { "stub" }
///     fn dispatch(&self, _: &vyre::Program, _: &[Vec<u8>], _: &vyre::DispatchConfig) -> Result<Vec<Vec<u8>>, vyre::BackendError> {
///         Ok(vec![])
///     }
/// }
///
/// assert_eq!(Stub.version(), "unspecified");
/// ```
fn version(&self) -> &'static str {
"unspecified"
}
/// Operation ids this backend can execute without further lowering.
fn supported_ops(&self) -> &std::collections::HashSet<crate::ir::OpId> {
default_supported_ops()
}
// `fn dispatch_wgsl(...)` was removed after the conform legacy
// probes migrated to vyre IR. Raw WGSL is a wgpu-implementation
// detail, not part of the substrate-neutral `VyreBackend`
// contract; consumers that still need to run a raw WGSL string
// import `vyre_wgpu::WgslDispatchExt` and call it on the wgpu
// backend directly.
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
}
