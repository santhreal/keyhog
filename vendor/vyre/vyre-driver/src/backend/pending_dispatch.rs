//! Handle to a dispatch in flight.

use crate::backend::{private, BackendError};

/// Handle to a dispatch in flight. Returned by
/// [`VyreBackend::dispatch_async`].
///
/// Consumer shape:
///
/// ```no_run
/// # use std::sync::Arc;
/// # use vyre::{Program, VyreBackend, DispatchConfig};
/// # fn run(backend: Arc<dyn VyreBackend>, program: &Program) -> Result<(), vyre::BackendError> {
/// let pending = backend.dispatch_async(program, &[vec![0u8; 64]], &DispatchConfig::default())?;
/// while !pending.is_ready() {
///     // Host-side work overlaps with the GPU dispatch.
/// }
/// let _outputs = pending.await_result()?;
/// # Ok(())
/// # }
/// ```
///
/// Backends that do not overlap host and device work return a
/// trivially-ready handle built by the default
/// [`VyreBackend::dispatch_async`] implementation — the consumer code
/// above still works, just without the overlap.
pub trait PendingDispatch: private::Sealed + Send + Sync {
    /// Non-blocking probe. Returns `true` when
    /// [`PendingDispatch::await_result`] would complete without
    /// blocking the caller thread.
    ///
    /// Backends that cannot probe without cost (no map_async
    /// equivalent) return `true` unconditionally; consumers will
    /// simply block inside `await_result`.
    fn is_ready(&self) -> bool;

    /// Consume the handle and return the dispatch's output buffers.
    ///
    /// Blocks the caller thread until the dispatch completes. Calling
    /// this on a handle whose `is_ready` reports `true` does not
    /// block.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if the dispatch failed on the device.
    fn await_result(self: Box<Self>) -> Result<Vec<Vec<u8>>, BackendError>;
}

/// Default [`PendingDispatch`] adapter used by the synchronous
/// [`VyreBackend::dispatch_async`] default.
///
/// Holds the already-computed output buffers; `is_ready` is always
/// `true` and `await_result` returns the buffers verbatim.
pub(crate) struct ReadyPending {
    pub(crate) outputs: Vec<Vec<u8>>,
}

impl private::Sealed for ReadyPending {}

impl PendingDispatch for ReadyPending {
    fn is_ready(&self) -> bool {
        true
    }
    fn await_result(self: Box<Self>) -> Result<Vec<Vec<u8>>, BackendError> {
        Ok(self.outputs)
    }
}
