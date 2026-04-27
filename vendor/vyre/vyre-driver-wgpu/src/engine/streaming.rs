//! Host-ingress compatibility stream for chunked inputs.
//!
//! This module is not VYRE's canonical streaming model. It exists for callers
//! that still receive bytes through host memory and need a bounded bridge while
//! the device-resident megakernel queue is being used elsewhere. The stream
//! owns a compiled `WgpuPipeline` and keeps at most one chunk in flight.
//! Calling `HostIngressStream::push_chunk` starts GPU work for the new chunk,
//! then returns the previous chunk's completed output.
//!
//! The CPU side is limited to ingress orchestration: owning the worker queue,
//! handing byte chunks to wgpu, and collecting completion. It must not perform
//! parser, matcher, scheduler, retry, or analysis semantics. The canonical
//! VYRE path is `vyre-runtime::megakernel`: CPU launches/publishes descriptors,
//! while the GPU owns phase progression and execution.
//!
//! Worker-pool channel: `crossbeam-channel`. `std::sync::mpsc::Receiver` is
//! single-consumer — wrapping it in `Arc<Mutex<_>>` to let N workers drain
//! the same queue serialises wakeups on the mutex (the audit called this
//! "Mutex<mpsc::Receiver> locking every recv"). crossbeam-channel is
//! multi-producer multi-consumer natively, so N workers do N independent
//! lock-free recvs.

use std::sync::{Arc, LazyLock};

use crossbeam_channel::{bounded, Receiver, Sender};
use vyre_driver::{BackendError, CompiledPipeline, DispatchConfig};

use crate::pipeline::WgpuPipeline;

/// Async copy stream primitives.
pub mod async_copy;

/// Host-ingress adapter for one in-flight chunked dispatch stream.
///
/// This is a compatibility adapter for environments where input bytes arrive
/// through host memory. It is intentionally named after ingress, not execution:
/// the device-resident execution model lives in `vyre-runtime::megakernel`.
pub struct HostIngressStream {
    runner:
        Arc<dyn Fn(Vec<u8>, DispatchConfig) -> Result<Vec<Vec<u8>>, BackendError> + Send + Sync>,
    config: DispatchConfig,
    in_flight: Option<Receiver<Result<Vec<Vec<u8>>, BackendError>>>,
}

/// Backwards-compatible alias for the old host-overlap name.
///
/// New code should use [`HostIngressStream`] when it specifically needs a
/// host-memory ingress bridge, or the megakernel queue for device-resident
/// streaming.
#[deprecated(
    since = "0.6.0",
    note = "renamed to HostIngressStream; canonical VYRE streaming is the device-resident megakernel queue"
)]
pub type StreamingDispatch = HostIngressStream;

type ChunkResult = Result<Vec<Vec<u8>>, BackendError>;

struct ChunkJob {
    runner:
        Arc<dyn Fn(Vec<u8>, DispatchConfig) -> Result<Vec<Vec<u8>>, BackendError> + Send + Sync>,
    bytes: Vec<u8>,
    config: DispatchConfig,
    response: Sender<ChunkResult>,
}

struct StreamingPool {
    sender: Sender<ChunkJob>,
}

impl StreamingPool {
    fn global() -> Result<&'static Self, BackendError> {
        static POOL: LazyLock<Result<StreamingPool, BackendError>> =
            LazyLock::new(StreamingPool::new);
        POOL.as_ref().map_err(|e| BackendError::new(e.to_string()))
    }

    fn new() -> Result<Self, BackendError> {
        const JOB_QUEUE: usize = 64;
        let (sender, receiver) = bounded::<ChunkJob>(JOB_QUEUE);
        let workers = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .min(32)
            .max(1);
        for index in 0..workers {
            // Each worker owns its own `Receiver` handle — cloning is
            // cheap and every worker drains the same MPMC queue
            // without contending on a mutex.
            let receiver = receiver.clone();
            std::thread::Builder::new()
                .name(format!("vyre-wgpu-streaming-{index}"))
                .spawn(move || loop {
                    match receiver.recv() {
                        Ok(job) => {
                            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                (job.runner)(job.bytes, job.config)
                            }))
                            .unwrap_or_else(|_| {
                                Err(BackendError::new(
                                    "host-ingress worker panicked. Fix: inspect the chunk program and GPU driver logs.",
                                ))
                            });
                            if let Err(error) = job.response.send(result) {
                                tracing::error!(
                                    ?error,
                                    "host-ingress result was lost because the receiver dropped"
                                );
                            }
                        }
                        Err(_) => return, // All senders dropped; pool is shutting down.
                    }
                })
                .map_err(|e| {
                    BackendError::new(format!(
                        "failed to spawn vyre-wgpu streaming worker thread: {e}. Fix: reduce process thread count or increase system nproc limit."
                    ))
                })?;
        }
        Ok(Self { sender })
    }

    fn submit(
        &self,
        runner: Arc<
            dyn Fn(Vec<u8>, DispatchConfig) -> Result<Vec<Vec<u8>>, BackendError> + Send + Sync,
        >,
        bytes: Vec<u8>,
        config: DispatchConfig,
    ) -> Result<Receiver<ChunkResult>, BackendError> {
        let (sender, receiver) = bounded(1);
        let job = ChunkJob {
            runner,
            bytes,
            config,
            response: sender,
        };
        self.sender
            .send(job)
            .map_err(|error| {
                BackendError::new(format!(
                    "host-ingress worker pool is closed: {error}. Fix: recreate the process; the global stream pool only closes during shutdown."
                ))
            })?;
        Ok(receiver)
    }
}

impl HostIngressStream {
    /// Create a host-ingress stream from a compiled wgpu pipeline.
    #[must_use]
    pub fn new(pipeline: WgpuPipeline, config: DispatchConfig) -> Self {
        let runner = Arc::new(move |bytes: Vec<u8>, config: DispatchConfig| {
            pipeline.dispatch(&[bytes], &config)
        });
        Self {
            runner,
            config,
            in_flight: None,
        }
    }

    /// Create a host-ingress stream from a custom chunk runner.
    #[must_use]
    pub fn from_runner<F>(runner: F, config: DispatchConfig) -> Self
    where
        F: Fn(Vec<u8>, DispatchConfig) -> Result<Vec<Vec<u8>>, BackendError>
            + Send
            + Sync
            + 'static,
    {
        Self {
            runner: Arc::new(runner),
            config,
            in_flight: None,
        }
    }

    /// Push a host-memory chunk and return the previous chunk's output when
    /// one exists.
    ///
    /// # Errors
    ///
    /// Returns a backend error if the previous chunk failed or the worker
    /// thread panicked before reporting a backend result.
    pub fn push_chunk(&mut self, bytes: Vec<u8>) -> Result<Option<Vec<Vec<u8>>>, BackendError> {
        let previous = self.take_finished()?;
        let runner = Arc::clone(&self.runner);
        let config = self.config.clone();
        self.in_flight = Some(StreamingPool::global()?.submit(runner, bytes, config)?);
        Ok(previous)
    }

    /// Wait for the final in-flight chunk and return its output.
    ///
    /// # Errors
    ///
    /// Returns a backend error if the final chunk failed or the worker panicked.
    pub fn finish(&mut self) -> Result<Option<Vec<Vec<u8>>>, BackendError> {
        self.take_finished()
    }

    fn take_finished(&mut self) -> Result<Option<Vec<Vec<u8>>>, BackendError> {
        let Some(handle) = self.in_flight.take() else {
            return Ok(None);
        };
        handle.recv().map_err(|error| {
            BackendError::new(
                format!("host-ingress worker ended before sending a result: {error}. Fix: inspect worker-pool lifecycle and GPU driver logs."),
            )
        })?
        .map(Some)
    }
}
