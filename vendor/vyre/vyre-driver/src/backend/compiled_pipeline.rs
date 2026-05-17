//! Pre-compiled pipeline trait.

use crate::backend::{
    private, BackendError, DispatchConfig, OutputBuffers, Resource, TimedDispatchResult,
};
use smallvec::SmallVec;

/// A program that has been pre-compiled by a backend, ready for repeated
/// dispatch with new inputs without paying compilation cost on each call.
///
/// Build one with [`crate::pipeline::compile`]. Backends that override
/// [`crate::backend::VyreBackend::compile_native`] return a cached pipeline (skipping
/// shader compilation, pipeline-layout creation, and bind-group-layout
/// creation on every dispatch); backends that don't get a transparent
/// passthrough whose semantics are identical to repeated [`crate::backend::VyreBackend::dispatch`].
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
        let owned: SmallVec<[Vec<u8>; 8]> = inputs.iter().map(|input| (*input).to_vec()).collect();
        self.dispatch(&owned, config)
    }

    /// Dispatch with backend-owned timing.
    ///
    /// Default timing is host wall time. Native pipeline implementations may
    /// attach device elapsed time without exposing driver APIs to callers.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the backend cannot complete dispatch.
    fn dispatch_borrowed_timed(
        &self,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<TimedDispatchResult, BackendError> {
        let started = std::time::Instant::now();
        let outputs = self.dispatch_borrowed(inputs, config)?;
        Ok(TimedDispatchResult {
            outputs,
            wall_ns: started.elapsed().as_nanos() as u64,
            device_ns: None,
            enqueue_ns: None,
            wait_ns: None,
        })
    }

    /// Dispatch the precompiled pipeline with borrowed inputs and write
    /// outputs into caller-owned storage.
    ///
    /// Backends may override this to reuse output buffers across repeated
    /// dispatches. The default preserves the existing return-value contract and
    /// moves the returned vectors into `outputs`.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the backend cannot complete dispatch.
    fn dispatch_borrowed_into(
        &self,
        inputs: &[&[u8]],
        config: &DispatchConfig,
        outputs: &mut OutputBuffers,
    ) -> Result<(), BackendError> {
        let result = self.dispatch_borrowed(inputs, config)?;
        outputs.clear();
        outputs.extend(result);
        Ok(())
    }

    /// Dispatch several independent borrowed-input submissions for the same
    /// compiled program.
    ///
    /// Backends with native queues/streams should override this to enqueue the
    /// whole batch before waiting for readback. The default is intentionally
    /// semantic, not fast: it preserves bit-identical behavior for backends
    /// that only implement the single-dispatch path.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when any item cannot complete dispatch.
    fn dispatch_borrowed_batched(
        &self,
        batches: &[&[&[u8]]],
        config: &DispatchConfig,
    ) -> Result<Vec<OutputBuffers>, BackendError> {
        let mut outputs = Vec::with_capacity(batches.len());
        for batch in batches {
            outputs.push(self.dispatch_borrowed(batch, config)?);
        }
        Ok(outputs)
    }

    /// Dispatch the precompiled pipeline with mixed host/resident handles.
    ///
    /// This is the P-41 contract: keep control, ring, IO, and debug buffers
    /// GPU-resident across launches.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the backend cannot complete dispatch.
    fn dispatch_persistent_handles(
        &self,
        _inputs: &[Resource],
        _config: &DispatchConfig,
    ) -> Result<OutputBuffers, BackendError> {
        Err(BackendError::UnsupportedFeature {
            name: "persistent handle dispatch".to_string(),
            backend: "unspecified".to_string(),
        })
    }

    /// Dispatch several resident-handle submissions for the same compiled
    /// program.
    ///
    /// Native backends should override this to record/replay the batch through
    /// one device submission or graph replay. The default preserves semantics
    /// for backends that only implement the single-submission resident path.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when any item cannot complete dispatch.
    fn dispatch_persistent_handles_batched(
        &self,
        batches: &[&[Resource]],
        config: &DispatchConfig,
    ) -> Result<Vec<OutputBuffers>, BackendError> {
        let mut outputs = Vec::with_capacity(batches.len());
        for batch in batches {
            outputs.push(self.dispatch_persistent_handles(batch, config)?);
        }
        Ok(outputs)
    }
}
