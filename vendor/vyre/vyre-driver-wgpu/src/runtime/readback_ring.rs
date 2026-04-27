//! Async readback ring (Innovation I.5).
//!
//! Blocking readback submits a copy + device.poll(Wait) that stalls
//! the submit queue. Under high dispatch rate this ruins latency and
//! throughput — the GPU goes idle while the CPU waits.
//!
//! The readback ring threads N staging buffers. Dispatch \`i\` writes
//! to \`ring[i % N]\`; the copy submits immediately and readback
//! happens asynchronously via \`map_async\`. Dispatch \`i+1\` runs in
//! parallel with readback \`i\`'s copy.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use vyre_driver::backend::BackendError;

const MIN_RING_SIZE: usize = 2;
const MAX_RING_SIZE: usize = 256;
const SLOT_FREE: u8 = 0;
const SLOT_PENDING: u8 = 1;
const SLOT_READY: u8 = 2;
const SLOT_ERROR: u8 = 3;

/// Statistics collected by the ring at runtime.
#[derive(Debug, Default)]
pub struct RingStats {
    /// Total dispatches queued.
    pub dispatches: AtomicU64,
    /// Readbacks that blocked waiting on map_async.
    pub readback_stalls: AtomicU64,
    /// Max outstanding (in-flight) copies.
    pub peak_inflight: AtomicU64,
}

impl RingStats {
    /// Record one dispatch; returns the monotonic dispatch index.
    pub fn record_dispatch(&self) -> u64 {
        self.dispatches.fetch_add(1, Ordering::AcqRel)
    }

    /// Record a stall.
    pub fn record_stall(&self) {
        self.readback_stalls.fetch_add(1, Ordering::Relaxed);
    }

    /// Update the peak-in-flight watermark.
    pub fn update_peak(&self, current: u64) {
        let mut prev = self.peak_inflight.load(Ordering::Relaxed);
        while current > prev {
            match self.peak_inflight.compare_exchange_weak(
                prev,
                current,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(now) => prev = now,
            }
        }
    }
}

/// Lifecycle state for one ring slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    /// Slot is available for new writes.
    Free,
    /// Copy has been submitted, data will be ready after fence.
    Pending,
    /// Map has completed and data is visible to the host.
    Ready,
    /// Mapping failed and the slot must be collected as an error.
    Error,
}

/// GPU-aware ring slot.
pub struct GpuSlot {
    /// Underlying wgpu buffer.
    pub buffer: wgpu::Buffer,
    /// Atomic lifecycle state (0: Free, 1: Pending, 2: Ready).
    pub state: Arc<std::sync::atomic::AtomicU8>,
}

/// Async readback ring buffer with GPU-resident staging buffers.
pub struct ReadbackRing {
    slots: Vec<GpuSlot>,
    stats: Arc<RingStats>,
    next_idx: usize,
}

impl ReadbackRing {
    /// Construct a ring with N staging buffers.
    #[must_use]
    pub fn new(device: &wgpu::Device, size: usize, buffer_size: u64) -> Self {
        let size = size.clamp(MIN_RING_SIZE, MAX_RING_SIZE);
        let mut slots = Vec::with_capacity(size);
        for i in 0..size {
            let buffer = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some(&format!("vyre readback ring slot {i}")),
                size: buffer_size,
                usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
                mapped_at_creation: false,
            });
            slots.push(GpuSlot {
                buffer,
                state: Arc::new(std::sync::atomic::AtomicU8::new(SLOT_FREE)),
            });
        }
        Self {
            slots,
            stats: Arc::new(RingStats::default()),
            next_idx: 0,
        }
    }

    /// Submit a copy and mark the slot pending.
    ///
    /// # Errors
    /// Returns [\`BackendError\`] if encoder or queue submission fails.
    pub fn submit_readback(
        &mut self,
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        src_buffer: &wgpu::Buffer,
        byte_len: u64,
    ) -> Result<usize, BackendError> {
        let idx = self.next_idx;
        let slot = &self.slots[idx];

        while slot.state.load(Ordering::Acquire) == SLOT_PENDING {
            self.stats.record_stall();
            match device.poll(wgpu::Maintain::Wait) {
                wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => {}
            }
        }

        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("vyre readback ring copy"),
        });
        encoder.copy_buffer_to_buffer(src_buffer, 0, &slot.buffer, 0, byte_len);
        queue.submit(std::iter::once(encoder.finish()));

        let state_clone = Arc::clone(&slot.state);
        state_clone.store(SLOT_PENDING, Ordering::Release);

        slot.buffer
            .slice(..byte_len)
            .map_async(wgpu::MapMode::Read, move |result| {
                match result {
                    Ok(()) => state_clone.store(SLOT_READY, Ordering::Release),
                    Err(error) => {
                        tracing::error!(
                            "readback ring map_async failed: {error:?}. Fix: inspect device health and readback buffer usage."
                        );
                        state_clone.store(SLOT_ERROR, Ordering::Release);
                    }
                }
            });

        self.next_idx = (idx + 1) % self.slots.len();
        self.stats.record_dispatch();

        Ok(idx)
    }

    /// Try to collect data from a specific slot.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when `idx` is out of bounds or `map_async`
    /// failed for the slot.
    pub fn collect_slot(
        &self,
        device: &wgpu::Device,
        idx: usize,
    ) -> Result<Option<Vec<u8>>, BackendError> {
        let Some(slot) = self.slots.get(idx) else {
            return Err(BackendError::new(format!(
                "readback ring slot index {idx} is out of bounds for {} slots. Fix: collect only indices returned by submit_readback.",
                self.slots.len()
            )));
        };
        match slot.state.load(Ordering::Acquire) {
            SLOT_READY => {
                let view = slot.buffer.slice(..).get_mapped_range();
                let data = view.to_vec();
                drop(view);
                slot.buffer.unmap();
                slot.state.store(SLOT_FREE, Ordering::Release);
                Ok(Some(data))
            }
            SLOT_ERROR => {
                slot.state.store(SLOT_FREE, Ordering::Release);
                Err(BackendError::new(
                    "readback ring map_async failed. Fix: inspect GPU device health and ensure the slot buffer has MAP_READ usage.",
                ))
            }
            _ => {
                match device.poll(wgpu::Maintain::Poll) {
                    wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => {}
                }
                Ok(None)
            }
        }
    }
}
