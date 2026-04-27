//! Pre-compiled pipeline trait.

use crate::backend::{private, BackendError, DispatchConfig};

/// A program that has been pre-compiled by a backend, ready for repeated
/// dispatch with new inputs without paying compilation cost on each call.
///
/// Build one with [`crate::pipeline::compile`]. Backends that override
/// [`VyreBackend::compile_native`] return a cached pipeline (skipping
/// shader compilation, pipeline-layout creation, and bind-group-layout
/// creation on every dispatch); backends that don't get a transparent
/// passthrough whose semantics are identical to repeated `VyreBackend::dispatch`.
///
/// `CompiledPipeline::dispatch` MUST be bit-identical to
/// `VyreBackend::dispatch(program, inputs, config)` for the program this
/// pipeline was compiled from. Any divergence is a backend bug.
pub trait CompiledPipeline: private::Sealed + Send + Sync {
    /// Stable identifier for this pipeline (typically `<backend>:<program-fingerprint>`).
    ///
    /// Used by certificates and debugging to confirm a particular cached
    /// pipeline was reused vs recompiled.
    fn id(&self) -> &str;

    /// Dispatch the precompiled pipeline with new inputs.
    ///
    /// Bit-identical to `VyreBackend::dispatch(self.program, inputs, config)`.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the backend cannot complete dispatch.
    /// The error message always includes a `Fix: ` remediation section.
    fn dispatch(
        &self,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError>;

    /// Dispatch the precompiled pipeline with borrowed input buffers.
    ///
    /// Backends may override this to bind caller-owned byte slices directly.
    /// The default allocates the owned input vector once, preserving the
    /// existing [`CompiledPipeline::dispatch`] contract for current backends.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the backend cannot complete dispatch.
    fn dispatch_borrowed(
        &self,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        let owned: Vec<Vec<u8>> = inputs.iter().map(|input| (*input).to_vec()).collect();
        self.dispatch(&owned, config)
    }
}
