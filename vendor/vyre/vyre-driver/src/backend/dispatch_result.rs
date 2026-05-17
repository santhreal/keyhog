//! Dispatch output payloads shared by every backend.

/// Output of one dispatch: a vector per output buffer slot, each
/// vector holding the raw bytes read back from the GPU. Consumers
/// (surgec, weir tests, etc.) decode the bytes per the Program's
/// output buffer declarations. The outer vec is indexed in the same
/// order as the Program's `is_output: true` buffers.
pub type OutputBuffers = Vec<Vec<u8>>;

/// Output plus timing captured by a backend-owned dispatch path.
///
/// `wall_ns` is always populated by the shared default implementation.
/// `device_ns` is populated only when a backend can measure elapsed device
/// stream time without crossing the driver boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimedDispatchResult {
    /// Output buffers in the same order as [`crate::backend::VyreBackend::dispatch`].
    pub outputs: OutputBuffers,
    /// Host-observed dispatch duration.
    pub wall_ns: u64,
    /// Device-observed elapsed time when the backend exposes a timer.
    pub device_ns: Option<u64>,
    /// Host time spent enqueueing backend work before the caller begins
    /// waiting for completion.
    pub enqueue_ns: Option<u64>,
    /// Host time spent waiting for completion and collecting output buffers.
    pub wait_ns: Option<u64>,
}
