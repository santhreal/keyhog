//! Async readback ring (Innovation I.5).
//!
//! Replaces blocking GPU readbacks with a pipelined slot model. A dispatch
//! lands in slot N; the caller arrives at slot N+1 and checks for readiness;
//! map_async happens in the background. This allows zero host-stalls during
//! high-frequency scanning.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use vyre_driver::BackendError;

const SLOT_PENDING: u8 = 0;
const SLOT_READY: u8 = 1;
const SLOT_ERROR: u8 = 2;

/// A slot in the async readback ring.
pub struct RingSlot {
    /// The buffer being read back.
    pub buffer: wgpu::Buffer,
    /// Completion fence.
    pub state: Arc<AtomicU8>,
}

/// Pipelined command submission and readback ring.
pub struct ReadbackRing {
    slots: VecDeque<RingSlot>,
    capacity: usize,
}

impl ReadbackRing {
    /// Create a new ring with the given slot capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            slots: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Submit a command buffer and associate it with a readback slot.
    pub fn submit_and_map(
        &mut self,
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        encoder: wgpu::CommandEncoder,
        output_buffer: wgpu::Buffer,
    ) -> Result<(), BackendError> {
        let state = Arc::new(AtomicU8::new(SLOT_PENDING));
        let state_clone = Arc::clone(&state);

        output_buffer.slice(..).map_async(wgpu::MapMode::Read, move |result| {
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

        queue.submit(std::iter::once(encoder.finish()));

        if self.slots.len() >= self.capacity {
            self.slots.pop_front();
        }

        self.slots.push_back(RingSlot {
            buffer: output_buffer,
            state,
        });

        Ok(())
    }

    /// Poll the oldest slot in the ring.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the oldest readback's `map_async`
    /// callback reports a mapping failure.
    pub fn poll_oldest(&mut self, device: &wgpu::Device) -> Result<Option<Vec<u8>>, BackendError> {
        let Some(slot) = self.slots.front() else {
            return Ok(None);
        };
        match slot.state.load(Ordering::Acquire) {
            SLOT_READY => {
                let Some(slot) = self.slots.pop_front() else {
                    return Ok(None);
                };
                let view = slot.buffer.slice(..).get_mapped_range();
                let data = view.to_vec();
                drop(view);
                slot.buffer.unmap();
                Ok(Some(data))
            }
            SLOT_ERROR => {
                self.slots.pop_front();
                Err(BackendError::new(
                    "readback ring map_async failed. Fix: inspect GPU device health and ensure the output buffer has MAP_READ usage.",
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
