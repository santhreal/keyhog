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

use crate::backend::telemetry::CudaTelemetry;
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
        let elapsed_ns = f64::from(elapsed_ms) * 1_000_000.0;
        if !elapsed_ns.is_finite() || elapsed_ns < 0.0 || elapsed_ns > u64::MAX as f64 {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA event elapsed time {elapsed_ms} ms cannot fit u64 nanoseconds; inspect CUDA event timing and split the dispatch before telemetry overflows."
                ),
            });
        }
        crate::numeric::rounded_f64_to_u64(elapsed_ns, "event elapsed nanoseconds")
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

/// Cached CUDA launch-resource counts retained for dispatch reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaLaunchResourceCounts {
    /// Cached non-blocking CUDA streams.
    pub streams: usize,
    /// Cached completion-fence CUDA events.
    pub completion_events: usize,
    /// Cached timing-enabled CUDA events used by graph replay telemetry.
    pub timing_events: usize,
}

/// Owned lease for launch resources before they are transferred into a pending dispatch.
#[derive(Debug)]
pub(crate) struct CudaLaunchResourceLease {
    pool: Arc<CudaLaunchResourcePool>,
    stream: Option<CudaStream>,
    timing_events: Option<(CudaEvent, CudaEvent)>,
}

/// Owned lease for a timing-event pair used outside normal launch-resource ownership.
#[derive(Debug)]
pub(crate) struct CudaTimingEventPairLease {
    pool: Arc<CudaLaunchResourcePool>,
    timing_events: Option<(CudaEvent, CudaEvent)>,
}

impl CudaTimingEventPairLease {
    pub(crate) fn acquire(pool: Arc<CudaLaunchResourcePool>) -> Result<Self, BackendError> {
        let timing_events = pool.acquire_timing_event_pair()?;
        Ok(Self {
            pool,
            timing_events: Some(timing_events),
        })
    }

    pub(crate) fn events(&self) -> Result<&(CudaEvent, CudaEvent), BackendError> {
        self.timing_events
            .as_ref()
            .ok_or_else(|| BackendError::InvalidProgram {
                fix: "Fix: CUDA timing event pair lease was already consumed; acquire a fresh timing lease before recording graph replay events.".to_string(),
            })
    }
}

impl Drop for CudaTimingEventPairLease {
    fn drop(&mut self) {
        if let Some((start, end)) = self.timing_events.take() {
            self.pool.release_timing_event(start);
            self.pool.release_timing_event(end);
        }
    }
}

impl CudaLaunchResourceLease {
    pub(crate) fn acquire(
        pool: Arc<CudaLaunchResourcePool>,
        capture_timing: bool,
    ) -> Result<Self, BackendError> {
        let stream = pool.acquire_stream()?;
        let timing_events = if capture_timing {
            match pool.acquire_timing_event_pair() {
                Ok(pair) => Some(pair),
                Err(error) => {
                    pool.release_stream(stream);
                    return Err(error);
                }
            }
        } else {
            None
        };
        Ok(Self {
            pool,
            stream: Some(stream),
            timing_events,
        })
    }

    pub(crate) fn stream_raw(&self) -> Result<CUstream, BackendError> {
        self.stream
            .as_ref()
            .map(CudaStream::raw)
            .ok_or_else(|| BackendError::InvalidProgram {
                fix: "Fix: CUDA launch resource lease stream was already consumed; acquire a fresh launch-resource lease before enqueueing CUDA work.".to_string(),
            })
    }

    pub(crate) fn timing_events(&self) -> Result<Option<&(CudaEvent, CudaEvent)>, BackendError> {
        if self.stream.is_none() {
            return Err(BackendError::InvalidProgram {
                fix: "Fix: CUDA launch resource lease timing events were queried after the stream was consumed; query timing events before transferring the lease into a pending dispatch.".to_string(),
            });
        }
        Ok(self.timing_events.as_ref())
    }

    pub(crate) fn into_parts(
        mut self,
    ) -> Result<(CudaStream, Option<(CudaEvent, CudaEvent)>), BackendError> {
        let stream = self.stream.take().ok_or_else(|| BackendError::InvalidProgram {
            fix: "Fix: CUDA launch resource lease stream was already consumed; pending dispatch ownership cannot be built twice from the same lease.".to_string(),
        })?;
        let timing_events = self.timing_events.take();
        Ok((stream, timing_events))
    }
}

impl Drop for CudaLaunchResourceLease {
    fn drop(&mut self) {
        if let Some((start, end)) = self.timing_events.take() {
            self.pool.release_timing_event(start);
            self.pool.release_timing_event(end);
        }
        if let Some(stream) = self.stream.take() {
            self.pool.release_stream(stream);
        }
    }
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

    pub(crate) fn acquire_timing_event_pair(&self) -> Result<(CudaEvent, CudaEvent), BackendError> {
        let start = self.acquire_timing_event()?;
        match self.acquire_timing_event() {
            Ok(end) => Ok((start, end)),
            Err(error) => {
                self.release_timing_event(start);
                Err(error)
            }
        }
    }

    pub(crate) fn release_stream(&self, stream: CudaStream) {
        if let Err(stream) = self.streams.push(stream) {
            drop(stream);
        }
    }

    pub(crate) fn release_event(&self, event: CudaEvent) {
        if let Err(event) = self.events.push(event) {
            drop(event);
        }
    }

    pub(crate) fn release_timing_event(&self, event: CudaEvent) {
        if let Err(event) = self.timing_events.push(event) {
            drop(event);
        }
    }

    pub(crate) fn cached_counts(&self) -> Result<(usize, usize), BackendError> {
        Ok((self.streams.len(), self.events.len()))
    }

    pub(crate) fn cached_counts_detailed(&self) -> Result<CudaLaunchResourceCounts, BackendError> {
        Ok(CudaLaunchResourceCounts {
            streams: self.streams.len(),
            completion_events: self.events.len(),
            timing_events: self.timing_events.len(),
        })
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
    telemetry: Arc<CudaTelemetry>,
    completed: AtomicBool,
}

impl CudaPendingDispatch {
    /// Build an already-completed pending dispatch.
    pub(crate) fn new_ready(
        ctx: Arc<CudaContext>,
        pool: Arc<CudaLaunchResourcePool>,
        outputs: Vec<Vec<u8>>,
        telemetry: Arc<CudaTelemetry>,
    ) -> Self {
        Self {
            ctx,
            pool,
            event: None,
            stream: None,
            allocations: None,
            resident_use: None,
            host_transfers: None,
            outputs,
            timing_start: None,
            timing_end: None,
            telemetry,
            completed: AtomicBool::new(true),
        }
    }

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
        telemetry: Arc<CudaTelemetry>,
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
            telemetry,
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
        telemetry: Arc<CudaTelemetry>,
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
            telemetry,
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
        if self.completed.load(Ordering::Acquire) {
            return Ok(());
        }
        self.bind_context()?;
        let event = self
            .event
            .as_ref()
            .ok_or_else(|| BackendError::DispatchFailed {
                code: None,
                message: "CUDA pending dispatch completion event was already released".to_string(),
            })?;
        event.synchronize()?;
        self.telemetry.record_sync_point();
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
        let outputs = self.collect_outputs()?;
        self.host_transfers.take();
        Ok((outputs, device_ns))
    }

    fn collect_outputs(&mut self) -> Result<Vec<Vec<u8>>, BackendError> {
        if let Some(transfers) = self.host_transfers.as_ref() {
            let mut outputs = std::mem::take(&mut self.outputs);
            transfers.collect_outputs_into(&mut outputs)?;
            Ok(outputs)
        } else {
            Ok(std::mem::take(&mut self.outputs))
        }
    }

    fn collect_outputs_into(&mut self, outputs: &mut Vec<Vec<u8>>) -> Result<(), BackendError> {
        if let Some(transfers) = self.host_transfers.as_ref() {
            transfers.collect_outputs_into(outputs)?;
        } else {
            vyre_driver::replace_output_buffers_preserving_slots(
                std::mem::take(&mut self.outputs),
                outputs,
            );
        }
        Ok(())
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
        let outputs = self.collect_outputs()?;
        self.host_transfers.take();
        Ok(outputs)
    }

    fn await_result_into(
        mut self: Box<Self>,
        outputs: &mut Vec<Vec<u8>>,
    ) -> Result<(), BackendError> {
        self.synchronize()?;
        self.release_launch_resources();
        self.allocations.take();
        self.resident_use.take();
        self.collect_outputs_into(outputs)?;
        self.host_transfers.take();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::CudaLaunchResourcePool;

    #[test]
    fn launch_resource_leases_do_not_panic_on_consumed_state() {
        let source = include_str!("stream.rs");
        assert!(
            !source.contains(concat!(".expect", "(\"Fix: CUDA launch resource lease stream was already consumed")),
            "Fix: CUDA launch resource leases must return typed backend errors when consumed twice, not panic."
        );
        assert!(
            !source.contains(concat!(".expect", "(\"Fix: CUDA timing event pair lease was already consumed")),
            "Fix: CUDA graph replay timing leases must return typed backend errors when consumed twice, not panic."
        );
    }

    #[test]
    fn launch_resource_counts_include_timing_events() {
        let pool = CudaLaunchResourcePool::new(8);
        let counts = pool
            .cached_counts_detailed()
            .expect("empty launch resource pool counts should be readable");

        assert_eq!(counts.streams, 0);
        assert_eq!(counts.completion_events, 0);
        assert_eq!(counts.timing_events, 0);

        let source = include_str!("stream.rs");
        assert!(
            source.contains("pub struct CudaLaunchResourceCounts")
                && source.contains("pub timing_events: usize")
                && source.contains("cached_counts_detailed"),
            "Fix: CUDA launch-resource telemetry must expose timing-event cache pressure, not just streams and completion events."
        );
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
                } else {
                    self.telemetry.record_sync_point();
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
