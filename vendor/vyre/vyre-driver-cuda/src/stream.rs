//! CUDA stream/event ownership and pending-dispatch handles.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use crossbeam_queue::ArrayQueue;
use cudarc::driver::{
    sys::{CUevent, CUevent_flags, CUresult, CUstream, CUstream_flags},
    CudaContext,
};
use vyre_driver::{backend::private, BackendError, PendingDispatch};

use crate::backend::{cuda_check, DispatchAllocations, HostTransferAllocations, ResidentUseGuard};

/// RAII owner for a CUDA stream.
#[derive(Debug)]
pub(crate) struct CudaStream {
    raw: CUstream,
}

unsafe impl Send for CudaStream {}
unsafe impl Sync for CudaStream {}

impl CudaStream {
    /// Create a non-blocking CUDA stream.
    pub(crate) fn non_blocking() -> Result<Self, BackendError> {
        let mut raw = std::ptr::null_mut();
        // SAFETY: stream / event handles are owned by &self; cuStream*/cuEvent* calls
        // operate on those owned handles and the result is checked via cuda_check.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuStreamCreate(
                    &mut raw,
                    CUstream_flags::CU_STREAM_NON_BLOCKING as u32,
                ),
                "cuStreamCreate",
            )?;
        }
        Ok(Self { raw })
    }

    /// Raw CUDA stream handle.
    #[must_use]
    pub(crate) fn raw(&self) -> CUstream {
        self.raw
    }

    /// Block until stream work has completed.
    pub(crate) fn synchronize(&self) -> Result<(), BackendError> {
        // SAFETY: stream / event handles are owned by &self; cuStream*/cuEvent* calls
        // operate on those owned handles and the result is checked via cuda_check.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuStreamSynchronize(self.raw),
                "cuStreamSynchronize",
            )
        }
    }
}

impl Drop for CudaStream {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: stream / event handles are owned by &self; cuStream*/cuEvent* calls
            // operate on those owned handles and the result is checked via cuda_check.
            unsafe {
                let result = cudarc::driver::sys::cuStreamDestroy_v2(self.raw);
                if result != CUresult::CUDA_SUCCESS {
                    eprintln!(
                        "Fix: cuStreamDestroy_v2 failed during CUDA stream drop with {result:?}; ensure pending work is synchronized before dropping dispatch resources."
                    );
                }
            }
        }
    }
}

/// RAII owner for a CUDA event used as the completion fence.
#[derive(Debug)]
pub(crate) struct CudaEvent {
    raw: CUevent,
}

unsafe impl Send for CudaEvent {}
unsafe impl Sync for CudaEvent {}

impl CudaEvent {
    /// Create a timing-disabled CUDA event.
    pub(crate) fn completion() -> Result<Self, BackendError> {
        let mut raw = std::ptr::null_mut();
        // SAFETY: stream / event handles are owned by &self; cuStream*/cuEvent* calls
        // operate on those owned handles and the result is checked via cuda_check.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuEventCreate(
                    &mut raw,
                    CUevent_flags::CU_EVENT_DISABLE_TIMING as u32,
                ),
                "cuEventCreate",
            )?;
        }
        Ok(Self { raw })
    }

    /// Create a CUDA event with timing enabled.
    pub(crate) fn timing() -> Result<Self, BackendError> {
        let mut raw = std::ptr::null_mut();
        // SAFETY: event handle is initialized by CUDA and checked before use.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuEventCreate(&mut raw, 0),
                "cuEventCreate",
            )?;
        }
        Ok(Self { raw })
    }

    /// Record this event onto a stream.
    pub(crate) fn record(&self, stream: CUstream) -> Result<(), BackendError> {
        // SAFETY: stream / event handles are owned by &self; cuStream*/cuEvent* calls
        // operate on those owned handles and the result is checked via cuda_check.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuEventRecord(self.raw, stream),
                "cuEventRecord",
            )
        }
    }

    /// Return whether all prior work in the stream has completed.
    #[must_use]
    pub(crate) fn is_ready(&self) -> bool {
        // SAFETY: stream / event handles are owned by &self; cuStream*/cuEvent* calls
        // operate on those owned handles and the result is checked via cuda_check.
        let result = unsafe { cudarc::driver::sys::cuEventQuery(self.raw) };
        matches!(result, CUresult::CUDA_SUCCESS)
    }

    /// Block until the event completes.
    pub(crate) fn synchronize(&self) -> Result<(), BackendError> {
        // SAFETY: stream / event handles are owned by &self; cuStream*/cuEvent* calls
        // operate on those owned handles and the result is checked via cuda_check.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuEventSynchronize(self.raw),
                "cuEventSynchronize",
            )
        }
    }

    /// Elapsed time between two timing-enabled events, in nanoseconds.
    pub(crate) fn elapsed_time_ns(&self, end: &CudaEvent) -> Result<u64, BackendError> {
        let mut elapsed_ms = 0.0f32;
        // SAFETY: both events are owned, valid CUDA event handles. CUDA returns an
        // error if either event was not recorded or timing was disabled.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuEventElapsedTime(
                    (&mut elapsed_ms) as *mut f32,
                    self.raw,
                    end.raw,
                ),
                "cuEventElapsedTime",
            )?;
        }
        Ok((elapsed_ms * 1_000_000.0) as u64)
    }
}

impl Drop for CudaEvent {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: stream / event handles are owned by &self; cuStream*/cuEvent* calls
            // operate on those owned handles and the result is checked via cuda_check.
            unsafe {
                let result = cudarc::driver::sys::cuEventDestroy_v2(self.raw);
                if result != CUresult::CUDA_SUCCESS {
                    eprintln!(
                        "Fix: cuEventDestroy_v2 failed during CUDA event drop with {result:?}; ensure pending work is synchronized before dropping dispatch resources."
                    );
                }
            }
        }
    }
}

/// Cached CUDA launch resources for repeated dispatches.
#[derive(Debug)]
pub(crate) struct CudaLaunchResourcePool {
    streams: ArrayQueue<CudaStream>,
    events: ArrayQueue<CudaEvent>,
    timing_events: ArrayQueue<CudaEvent>,
}

impl CudaLaunchResourcePool {
    pub(crate) fn new(max_cached: usize) -> Self {
        let max_cached = max_cached.max(1);
        Self {
            streams: ArrayQueue::new(max_cached),
            events: ArrayQueue::new(max_cached),
            timing_events: ArrayQueue::new(max_cached),
        }
    }

    pub(crate) fn acquire_stream(&self) -> Result<CudaStream, BackendError> {
        if let Some(stream) = self.streams.pop() {
            return Ok(stream);
        }
        CudaStream::non_blocking()
    }

    pub(crate) fn acquire_event(&self) -> Result<CudaEvent, BackendError> {
        if let Some(event) = self.events.pop() {
            return Ok(event);
        }
        CudaEvent::completion()
    }

    pub(crate) fn acquire_timing_event(&self) -> Result<CudaEvent, BackendError> {
        if let Some(event) = self.timing_events.pop() {
            return Ok(event);
        }
        CudaEvent::timing()
    }

    pub(crate) fn release_stream(&self, stream: CudaStream) {
        if let Err(stream) = self.streams.push(stream) {
            drop(stream);
        }
    }

    fn release_event(&self, event: CudaEvent) {
        if let Err(event) = self.events.push(event) {
            drop(event);
        }
    }

    fn release_timing_event(&self, event: CudaEvent) {
        if let Err(event) = self.timing_events.push(event) {
            drop(event);
        }
    }

    pub(crate) fn cached_counts(&self) -> Result<(usize, usize), BackendError> {
        Ok((self.streams.len(), self.events.len()))
    }

    pub(crate) fn clear(&self) -> Result<(), BackendError> {
        while self.streams.pop().is_some() {}
        while self.events.pop().is_some() {}
        while self.timing_events.pop().is_some() {}
        Ok(())
    }
}

/// CUDA-backed pending dispatch whose result is fenced by a CUDA event.
#[derive(Debug)]
pub(crate) struct CudaPendingDispatch {
    ctx: Arc<CudaContext>,
    pool: Arc<CudaLaunchResourcePool>,
    event: Option<CudaEvent>,
    stream: Option<CudaStream>,
    allocations: Option<DispatchAllocations>,
    resident_use: Option<ResidentUseGuard>,
    host_transfers: Option<HostTransferAllocations>,
    outputs: Vec<Vec<u8>>,
    timing_start: Option<CudaEvent>,
    timing_end: Option<CudaEvent>,
    completed: AtomicBool,
}

impl CudaPendingDispatch {
    /// Build a pending dispatch after all GPU work has been enqueued.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        ctx: Arc<CudaContext>,
        pool: Arc<CudaLaunchResourcePool>,
        event: CudaEvent,
        stream: CudaStream,
        allocations: DispatchAllocations,
        resident_use: Option<ResidentUseGuard>,
        host_transfers: Option<HostTransferAllocations>,
        outputs: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            ctx,
            pool,
            event: Some(event),
            stream: Some(stream),
            allocations: Some(allocations),
            resident_use,
            host_transfers,
            outputs,
            timing_start: None,
            timing_end: None,
            completed: AtomicBool::new(false),
        }
    }

    /// Build a pending dispatch with timing-enabled start/end events.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_timing(
        ctx: Arc<CudaContext>,
        pool: Arc<CudaLaunchResourcePool>,
        event: CudaEvent,
        stream: CudaStream,
        allocations: DispatchAllocations,
        resident_use: Option<ResidentUseGuard>,
        host_transfers: Option<HostTransferAllocations>,
        outputs: Vec<Vec<u8>>,
        timing_start: CudaEvent,
        timing_end: CudaEvent,
    ) -> Self {
        Self {
            ctx,
            pool,
            event: Some(event),
            stream: Some(stream),
            allocations: Some(allocations),
            resident_use,
            host_transfers,
            outputs,
            timing_start: Some(timing_start),
            timing_end: Some(timing_end),
            completed: AtomicBool::new(false),
        }
    }

    fn bind_context(&self) -> Result<(), BackendError> {
        self.ctx
            .bind_to_thread()
            .map_err(|e| BackendError::DispatchFailed {
                code: None,
                message: format!("CUDA context bind failed: {e}"),
            })
    }

    fn synchronize(&self) -> Result<(), BackendError> {
        self.bind_context()?;
        let event = self
            .event
            .as_ref()
            .ok_or_else(|| BackendError::DispatchFailed {
                code: None,
                message: "CUDA pending dispatch completion event was already released".to_string(),
            })?;
        event.synchronize()?;
        self.completed.store(true, Ordering::Release);
        Ok(())
    }

    fn release_launch_resources(&mut self) {
        if let Some(event) = self.event.take() {
            self.pool.release_event(event);
        }
        if let Some(event) = self.timing_start.take() {
            self.pool.release_timing_event(event);
        }
        if let Some(event) = self.timing_end.take() {
            self.pool.release_timing_event(event);
        }
        if let Some(stream) = self.stream.take() {
            self.pool.release_stream(stream);
        }
    }

    /// Await completion and return output buffers plus device elapsed time.
    pub(crate) fn await_timed_result(
        mut self,
    ) -> Result<(Vec<Vec<u8>>, Option<u64>), BackendError> {
        self.synchronize()?;
        let device_ns = match (self.timing_start.as_ref(), self.timing_end.as_ref()) {
            (Some(start), Some(end)) => Some(start.elapsed_time_ns(end)?),
            _ => None,
        };
        self.release_launch_resources();
        self.allocations.take();
        self.resident_use.take();
        let outputs = self.collect_outputs();
        self.host_transfers.take();
        Ok((outputs, device_ns))
    }

    fn collect_outputs(&mut self) -> Vec<Vec<u8>> {
        if let Some(transfers) = self.host_transfers.as_ref() {
            let mut outputs = std::mem::take(&mut self.outputs);
            transfers.collect_outputs_into(&mut outputs);
            outputs
        } else {
            std::mem::take(&mut self.outputs)
        }
    }
}

impl private::Sealed for CudaPendingDispatch {}

impl PendingDispatch for CudaPendingDispatch {
    fn is_ready(&self) -> bool {
        if self.completed.load(Ordering::Acquire) {
            return true;
        }
        if self.bind_context().is_err() {
            return false;
        }
        let Some(event) = self.event.as_ref() else {
            return true;
        };
        let ready = event.is_ready();
        if ready {
            self.completed.store(true, Ordering::Release);
        }
        ready
    }

    fn await_result(mut self: Box<Self>) -> Result<Vec<Vec<u8>>, BackendError> {
        self.synchronize()?;
        self.release_launch_resources();
        self.allocations.take();
        self.resident_use.take();
        let outputs = self.collect_outputs();
        self.host_transfers.take();
        Ok(outputs)
    }
}

impl Drop for CudaPendingDispatch {
    fn drop(&mut self) {
        if !self.completed.load(Ordering::Acquire) {
            if let Err(error) = self.ctx.bind_to_thread() {
                eprintln!(
                    "Fix: failed to bind CUDA context while dropping pending dispatch: {error}. Dispatch completion could not be forced."
                );
            }
            if let Some(stream) = self.stream.as_ref() {
                if let Err(error) = stream.synchronize() {
                    eprintln!(
                        "Fix: failed to synchronize CUDA stream while dropping pending dispatch: {error}. Dispatch completion state may be stale."
                    );
                }
            }
            self.completed.store(true, Ordering::Release);
        }
        self.release_launch_resources();
        self.allocations.take();
        self.resident_use.take();
        self.host_transfers.take();
    }
}
