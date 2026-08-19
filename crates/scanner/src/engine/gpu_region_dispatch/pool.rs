//! Resident accelerator execution pool and permit management.
//!
//! Replaces single process-wide mutex serialization with a concurrency pool
//! sized from device capability and host concurrency (Row 118). Both direct
//! CLI scans and daemon scans take this pooled execution path so concurrent
//! region dispatches are bounded by real hardware capacity instead of a
//! process-wide critical section.

use crate::engine::gpu_forced::SelectedGpuDispatchError;
use crate::engine::ScannerBackendState;

#[derive(Debug)]
pub struct GpuResidentExecutionPool {
    capacity: usize,
    state: parking_lot::Mutex<GpuResidentExecutionPoolState>,
    available_cvar: parking_lot::Condvar,
}

#[derive(Debug)]
struct GpuResidentExecutionPoolState {
    available_permits: usize,
    in_flight: usize,
    peak_concurrency: usize,
    total_dispatches: u64,
    poisoned: bool,
}

#[derive(Debug)]
pub struct GpuResidentExecutionPermit<'a> {
    pool: &'a GpuResidentExecutionPool,
    acquired_at: std::time::Instant,
}

impl Drop for GpuResidentExecutionPermit<'_> {
    fn drop(&mut self) {
        self.pool.release();
    }
}

impl GpuResidentExecutionPermit<'_> {
    #[inline]
    #[must_use]
    pub fn acquired_at(&self) -> std::time::Instant {
        self.acquired_at
    }

    #[inline]
    #[must_use]
    pub fn elapsed(&self) -> std::time::Duration {
        self.acquired_at.elapsed()
    }
}

impl GpuResidentExecutionPool {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            state: parking_lot::Mutex::new(GpuResidentExecutionPoolState {
                available_permits: capacity,
                in_flight: 0,
                peak_concurrency: 0,
                total_dispatches: 0,
                poisoned: false,
            }),
            available_cvar: parking_lot::Condvar::new(),
        }
    }

    /// Derive pool capacity from device capability string, pipeline depth, and host concurrency.
    #[must_use]
    pub fn derive_capacity_for_device(
        dispatch_capability: &str,
        pipeline_depth: u8,
        host_concurrency: usize,
    ) -> usize {
        let host_concurrency = host_concurrency.max(1);
        match dispatch_capability {
            "async-submit-retire" => {
                let device_depth = usize::from(pipeline_depth).max(2);
                host_concurrency.min(device_depth.max(4)).clamp(1, 16)
            }
            "synchronous" => host_concurrency.clamp(1, 4),
            _ => host_concurrency.clamp(1, 4),
        }
    }

    /// Derive pool capacity from active scanner backend state and host concurrency.
    #[must_use]
    pub(crate) fn derive_capacity(
        backend_state: &ScannerBackendState,
        host_concurrency: usize,
    ) -> usize {
        let host_concurrency = host_concurrency.max(1);
        match backend_state {
            #[cfg(feature = "gpu")]
            ScannerBackendState::SelectedGpu { peer, .. } => {
                let is_software = peer.is_software;
                let available = peer.available;
                if !available || is_software {
                    host_concurrency.clamp(1, 4)
                } else {
                    host_concurrency.clamp(1, 16)
                }
            }
            #[cfg(feature = "gpu")]
            ScannerBackendState::Census { peers, .. } => {
                let has_hardware_gpu = (peers.cuda_available
                    && !peers
                        .cuda_runtime_identity
                        .as_deref()
                        .unwrap_or("")
                        .contains("cpu"))
                    || peers.metal_available
                    || (peers.wgpu_available && !peers.wgpu_is_software);
                if has_hardware_gpu {
                    host_concurrency.clamp(1, 16)
                } else {
                    host_concurrency.clamp(1, 4)
                }
            }
            _ => host_concurrency.clamp(1, 4),
        }
    }

    /// Construct pool for the active scanner backend state.
    #[must_use]
    pub(crate) fn for_backend_state(backend_state: &ScannerBackendState) -> Self {
        let host_concurrency = std::thread::available_parallelism()
            .map_or(4, std::num::NonZeroUsize::get);
        let capacity = Self::derive_capacity(backend_state, host_concurrency);
        Self::new(capacity)
    }

    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[inline]
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.state.lock().in_flight
    }

    #[inline]
    #[must_use]
    pub fn peak_concurrency(&self) -> usize {
        self.state.lock().peak_concurrency
    }

    #[inline]
    #[must_use]
    pub fn available_permits(&self) -> usize {
        self.state.lock().available_permits
    }

    #[inline]
    #[must_use]
    pub fn total_dispatches(&self) -> u64 {
        self.state.lock().total_dispatches
    }

    pub(crate) fn acquire(&self) -> Result<GpuResidentExecutionPermit<'_>, SelectedGpuDispatchError> {
        let mut state = self.state.lock();
        loop {
            if state.poisoned {
                return Err(SelectedGpuDispatchError::new(
                    "resident accelerator execution pool is unavailable after an internal panic",
                ));
            }
            if state.available_permits > 0 {
                state.available_permits -= 1;
                state.in_flight += 1;
                if state.in_flight > state.peak_concurrency {
                    state.peak_concurrency = state.in_flight;
                }
                state.total_dispatches = state.total_dispatches.saturating_add(1);
                return Ok(GpuResidentExecutionPermit {
                    pool: self,
                    acquired_at: std::time::Instant::now(),
                });
            }
            self.available_cvar.wait(&mut state);
        }
    }

    pub(crate) fn try_acquire(
        &self,
    ) -> Result<Option<GpuResidentExecutionPermit<'_>>, SelectedGpuDispatchError> {
        let mut state = self.state.lock();
        if state.poisoned {
            return Err(SelectedGpuDispatchError::new(
                "resident accelerator execution pool is unavailable after an internal panic",
            ));
        }
        if state.available_permits > 0 {
            state.available_permits -= 1;
            state.in_flight += 1;
            if state.in_flight > state.peak_concurrency {
                state.peak_concurrency = state.in_flight;
            }
            state.total_dispatches = state.total_dispatches.saturating_add(1);
            Ok(Some(GpuResidentExecutionPermit {
                pool: self,
                acquired_at: std::time::Instant::now(),
            }))
        } else {
            Ok(None)
        }
    }
    /// Acquire a permit from the pool, returning a human-readable error on poison.
    pub fn acquire_permit(&self) -> Result<GpuResidentExecutionPermit<'_>, String> {
        self.acquire().map_err(|err| err.to_string())
    }

    /// Try to acquire a permit from the pool without blocking.
    pub fn try_acquire_permit(&self) -> Result<Option<GpuResidentExecutionPermit<'_>>, String> {
        self.try_acquire().map_err(|err| err.to_string())
    }


    pub(crate) fn release(&self) {
        let mut state = self.state.lock();
        state.in_flight = state.in_flight.saturating_sub(1);
        state.available_permits = (state.available_permits + 1).min(self.capacity);
        self.available_cvar.notify_one();
    }

    pub fn poison(&self) {
        let mut state = self.state.lock();
        state.poisoned = true;
        self.available_cvar.notify_all();
    }
}
