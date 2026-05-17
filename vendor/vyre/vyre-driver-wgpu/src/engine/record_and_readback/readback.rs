use super::timestamp::{emit_timestamp_profile, PendingTimestampProfile};
use super::trap;
use crate::pipeline::OutputBindingLayout;
use crate::buffer::GpuBufferHandle;
use crossbeam_channel::Receiver;
use smallvec::SmallVec;
use std::ops::Range;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use vyre_driver::BackendError;
use vyre_emit_naga::program::TrapTag;

type MapResult = Result<(), wgpu::BufferAsyncError>;
pub(super) type PendingMap = (Option<usize>, PendingReadback);
pub(super) type SubmittedMap = (Option<usize>, SubmittedReadback);

pub(super) enum SubmittedReadback {
    Pooled {
        buffer: GpuBufferHandle,
        mapped_range: Range<u64>,
    },
    Ring {
        ring: Arc<crate::runtime::readback_ring::ReadbackRing>,
        ticket: crate::runtime::readback_ring::ReadbackTicket,
    },
}

pub(crate) enum PendingReadback {
    Pooled {
        buffer: GpuBufferHandle,
        receiver: Receiver<MapResult>,
        ready: Arc<AtomicBool>,
        mapped_range: Range<u64>,
    },
    Ring {
        ring: Arc<crate::runtime::readback_ring::ReadbackRing>,
        ticket: crate::runtime::readback_ring::ReadbackTicket,
        receiver: Receiver<crate::runtime::readback_ring::MapResult>,
        ready: Arc<AtomicBool>,
    },
}

impl SubmittedReadback {
    pub(super) fn map_async(self) -> Result<PendingReadback, BackendError> {
        match self {
            Self::Pooled {
                buffer,
                mapped_range,
            } => {
                let buf = buffer.buffer();
                let slice = buf.slice(mapped_range.start..mapped_range.end);
                let (sender, receiver) = crossbeam_channel::bounded(1);
                let ready = Arc::new(AtomicBool::new(false));
                let ready_cb = Arc::clone(&ready);
                slice.map_async(wgpu::MapMode::Read, move |result| {
                    if let Err(error) = sender.send(result) {
                        tracing::error!(
                            ?error,
                            "GPU readback callback result was lost because the receiver dropped"
                        );
                    }
                    ready_cb.store(true, Ordering::Release);
                });
                Ok(PendingReadback::Pooled {
                    buffer,
                    receiver,
                    ready,
                    mapped_range,
                })
            }
            Self::Ring { ring, ticket } => {
                let (receiver, ready) = ring.arm_ticket(&ticket)?;
                Ok(PendingReadback::Ring {
                    ring,
                    ticket,
                    receiver,
                    ready,
                })
            }
        }
    }
}

impl PendingReadback {
    fn is_ready(&self) -> bool {
        match self {
            Self::Pooled { ready, .. } | Self::Ring { ready, .. } => ready.load(Ordering::Acquire),
        }
    }

    fn with_mapped_bytes<R>(
        self,
        deadline: Instant,
        visitor: impl FnOnce(&[u8]) -> Result<R, BackendError>,
    ) -> Result<R, BackendError> {
        match self {
            Self::Pooled {
                buffer,
                receiver,
                mapped_range,
                ..
            } => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(BackendError::new(
                        "GPU readback map callback did not complete within 30s after submission wait. Fix: inspect wgpu device polling, driver health, and readback buffer lifetimes.",
                    ));
                }
                let map_result = receiver.recv_timeout(deadline - now).map_err(|error| {
                    BackendError::new(format!(
                        "GPU readback callback did not complete after submission wait: {error}. Fix: ensure readback receivers stay alive until device polling finishes and inspect GPU driver health."
                    ))
                })?;
                map_result.map_err(|e| {
                    BackendError::new(format!(
                        "GPU readback mapping failed: {e:?}. Fix: use MAP_READ and COPY_DST readback buffers."
                    ))
                })?;

                let buf = buffer.buffer();
                let slice = buf.slice(mapped_range);
                let mapped = slice.get_mapped_range();
                let result = visitor(&mapped);
                drop(mapped);
                buf.unmap();
                result
            }
            Self::Ring {
                ring,
                ticket,
                receiver,
                ..
            } => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(BackendError::new(
                        "GPU readback ring map callback did not complete within 30s after submission wait. Fix: inspect wgpu device polling, driver health, and readback ring lifetimes.",
                    ));
                }
                let map_result = receiver.recv_timeout(deadline - now).map_err(|error| {
                    BackendError::new(format!(
                        "GPU readback ring callback did not complete after submission wait: {error}. Fix: ensure readback ring tickets stay alive until device polling finishes and inspect GPU driver health."
                    ))
                })?;
                map_result.map_err(|e| {
                    BackendError::new(format!(
                        "GPU readback ring mapping failed: {e:?}. Fix: use MAP_READ and COPY_DST readback ring slots."
                    ))
                })?;
                ring.with_mapped_ticket(&ticket, visitor)
            }
        }
    }

    fn with_pooled_mapped_bytes<R>(
        self,
        deadline: Instant,
        visitor: impl FnOnce(&[u8]) -> Result<R, BackendError>,
    ) -> Result<(GpuBufferHandle, R), BackendError> {
        let Self::Pooled {
            buffer,
            receiver,
            mapped_range,
            ..
        } = self
        else {
            return Err(BackendError::new(
                "trap sidecar readback unexpectedly used the ring path. Fix: keep trap sidecars on pooled staging so full-sidecar lazy decode can remap the same buffer.",
            ));
        };
        let now = Instant::now();
        if now >= deadline {
            return Err(BackendError::new(
                "GPU trap readback map callback did not complete within 30s after submission wait. Fix: inspect wgpu device polling, driver health, and readback buffer lifetimes.",
            ));
        }
        let map_result = receiver.recv_timeout(deadline - now).map_err(|error| {
            BackendError::new(format!(
                "GPU trap readback callback did not complete after submission wait: {error}. Fix: ensure readback receivers stay alive until device polling finishes and inspect GPU driver health."
            ))
        })?;
        map_result.map_err(|e| {
            BackendError::new(format!(
                "GPU trap readback mapping failed: {e:?}. Fix: use MAP_READ and COPY_DST readback buffers."
            ))
        })?;

        let buf = buffer.buffer();
        let slice = buf.slice(mapped_range);
        let mapped = slice.get_mapped_range();
        let result = visitor(&mapped);
        drop(mapped);
        buf.unmap();
        Ok((buffer, result?))
    }
}

/// Handle for submitted wgpu work whose readback maps are still in flight.
pub(crate) struct WgpuPendingReadback {
    pub(super) device_queue: Arc<(wgpu::Device, wgpu::Queue)>,
    pub(super) pending: SmallVec<[PendingMap; 4]>,
    pub(super) outputs: vyre_driver::OutputBuffers,
    pub(super) output_count: usize,
    pub(super) output_bindings: Arc<[OutputBindingLayout]>,
    pub(super) trap_tags: Arc<[TrapTag]>,
    pub(super) timestamp_profile: Option<PendingTimestampProfile>,
}

impl WgpuPendingReadback {
    /// Non-blocking readiness probe.
    pub(crate) fn is_ready(&self) -> bool {
        let (device, _) = &*self.device_queue;
        match device.poll(wgpu::Maintain::Poll) {
            wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => {}
        }
        let outputs_ready = self.pending.iter().all(|(_, pending)| pending.is_ready());
        outputs_ready
            && self
                .timestamp_profile
                .as_ref()
                .map(|profile| profile.ready.load(Ordering::Acquire))
                .unwrap_or(true)
    }

    /// Wait for the GPU submission and collect trimmed output buffers.
    pub(crate) fn await_result(mut self) -> Result<vyre_driver::OutputBuffers, BackendError> {
        let mut outputs = std::mem::take(&mut self.outputs);
        self.await_into(&mut outputs)?;
        Ok(outputs)
    }

    /// Wait for the GPU submission and collect trimmed output buffers into
    /// caller-owned storage.
    pub(crate) fn await_into(
        self,
        outputs: &mut vyre_driver::OutputBuffers,
    ) -> Result<(), BackendError> {
        let deadline = Instant::now() + Duration::from_secs(30);
        self.poll_until_ready(deadline)?;
        self.collect_after_submission_wait(outputs, deadline)
    }

    /// Wait for the GPU submission and expose each trimmed mapped output slice
    /// to `visitor` before unmapping the staging buffer.
    pub(crate) fn await_mapped_outputs<F>(self, visitor: F) -> Result<(), BackendError>
    where
        F: FnMut(usize, &[u8]) -> Result<(), BackendError>,
    {
        let deadline = Instant::now() + Duration::from_secs(30);
        self.poll_until_ready(deadline)?;
        self.collect_mapped_after_submission_wait(visitor, deadline)
    }

    pub(crate) fn await_many_owned(
        pending: Vec<Self>,
    ) -> Vec<Result<vyre_driver::OutputBuffers, BackendError>> {
        let deadline = Self::wait_for_many(&pending);
        let mut results = Vec::with_capacity(pending.len());
        for mut readback in pending {
            let mut outputs = std::mem::take(&mut readback.outputs);
            results.push(
                readback
                    .collect_after_submission_wait(&mut outputs, deadline)
                    .map(|()| outputs),
            );
        }
        results
    }

    pub(crate) fn wait_for_many(pending: &[Self]) -> Instant {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut device_queues: SmallVec<[Arc<(wgpu::Device, wgpu::Queue)>; 4]> =
            SmallVec::with_capacity(pending.len().min(4));
        let mut backoff = ReadbackPollBackoff::new();
        for readback in pending {
            if !device_queues
                .iter()
                .any(|device_queue| Arc::ptr_eq(device_queue, &readback.device_queue))
            {
                device_queues.push(Arc::clone(&readback.device_queue));
            }
        }
        while Instant::now() < deadline {
            for device_queue in &device_queues {
                let (device, _) = &**device_queue;
                match device.poll(wgpu::Maintain::Poll) {
                    wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => {}
                }
            }
            if pending.iter().all(Self::readback_ready) {
                return deadline;
            }
            backoff.idle(deadline);
        }
        deadline
    }

    fn readback_ready(readback: &Self) -> bool {
        readback
            .pending
            .iter()
            .all(|(_, pending)| pending.is_ready())
            && readback
                .timestamp_profile
                .as_ref()
                .map(|profile| profile.ready.load(Ordering::Acquire))
                .unwrap_or(true)
    }

    fn poll_until_ready(&self, deadline: Instant) -> Result<(), BackendError> {
        let (device, _) = &*self.device_queue;
        let mut backoff = ReadbackPollBackoff::new();
        while Instant::now() < deadline {
            match device.poll(wgpu::Maintain::Poll) {
                wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => {}
            }
            let outputs_ready = self.pending.iter().all(|(_, pending)| pending.is_ready());
            let timestamps_ready = self
                .timestamp_profile
                .as_ref()
                .map(|profile| profile.ready.load(Ordering::Acquire))
                .unwrap_or(true);
            if outputs_ready && timestamps_ready {
                return Ok(());
            }
            backoff.idle(deadline);
        }
        Err(BackendError::new(
            "GPU readback callbacks did not complete within 30s. Fix: inspect wgpu device polling, driver health, and command-buffer liveness.",
        ))
    }

    pub(crate) fn output_count(&self) -> usize {
        self.output_count
    }

    pub(crate) fn collect_after_submission_wait(
        self,
        outputs: &mut vyre_driver::OutputBuffers,
        deadline: Instant,
    ) -> Result<(), BackendError> {
        let (device, _) = &*self.device_queue;
        let output_count = self.output_count();
        let trap_tags = self.trap_tags;
        let timestamp_profile = self.timestamp_profile;
        if outputs.len() < output_count {
            outputs.resize_with(output_count, Vec::new);
        } else {
            outputs.truncate(output_count);
        }
        let mut output_index = 0usize;
        for (output_idx, pending) in self.pending {
            if let Some(output_idx) = output_idx {
                let output = self.output_bindings.get(output_idx).ok_or_else(|| {
                    BackendError::new(format!(
                        "readback output index {output_idx} is out of bounds. Fix: keep output binding metadata alive with pending readbacks."
                    ))
                })?;
                pending.with_mapped_bytes(deadline, |mapped| {
                    let trim = output.layout.trim_start;
                    let end = trim.saturating_add(output.layout.read_size);
                    if end > mapped.len() {
                        return Err(BackendError::new(format!(
                            "readback slice for output `{}` is out of bounds. Fix: verify OutputLayout against actual GPU readback size.",
                            output.name
                        )));
                    }
                    let read_len = end - trim;
                    let out = &mut outputs[output_index];
                    out.clear();
                    out.reserve(read_len);
                    out.extend_from_slice(&mapped[trim..end]);
                    Ok(())
                })?;
                output_index = output_index.saturating_add(1);
            } else {
                let (readback_buffer, trap_flag) =
                    pending.with_pooled_mapped_bytes(deadline, trap::sidecar_flag_set)?;
                if trap_flag {
                    if let Some(error) =
                        trap::map_full_sidecar(device, &readback_buffer, deadline, &trap_tags)?
                    {
                        return Err(error);
                    }
                }
                continue;
            }
        }

        emit_timestamp_profile(timestamp_profile, deadline)?;
        Ok(())
    }

    pub(crate) fn collect_mapped_after_submission_wait<F>(
        self,
        mut visitor: F,
        deadline: Instant,
    ) -> Result<(), BackendError>
    where
        F: FnMut(usize, &[u8]) -> Result<(), BackendError>,
    {
        let (device, _) = &*self.device_queue;
        let trap_tags = self.trap_tags;
        let timestamp_profile = self.timestamp_profile;
        let mut output_index = 0usize;
        for (output_idx, pending) in self.pending {
            if let Some(output_idx) = output_idx {
                let output = self.output_bindings.get(output_idx).ok_or_else(|| {
                    BackendError::new(format!(
                        "readback output index {output_idx} is out of bounds. Fix: keep output binding metadata alive with pending readbacks."
                    ))
                })?;
                let visitor_result = pending.with_mapped_bytes(deadline, |mapped| {
                    let trim = output.layout.trim_start;
                    let end = trim.saturating_add(output.layout.read_size);
                    if end > mapped.len() {
                        return Err(BackendError::new(format!(
                            "readback slice for output `{}` is out of bounds. Fix: verify OutputLayout against actual GPU readback size.",
                            output.name
                        )));
                    }
                    visitor(output_index, &mapped[trim..end])
                });
                output_index = output_index.saturating_add(1);
                visitor_result?;
            } else {
                let (readback_buffer, trap_flag) =
                    pending.with_pooled_mapped_bytes(deadline, trap::sidecar_flag_set)?;
                if trap_flag {
                    if let Some(error) =
                        trap::map_full_sidecar(device, &readback_buffer, deadline, &trap_tags)?
                    {
                        return Err(error);
                    }
                }
                continue;
            }
        }

        emit_timestamp_profile(timestamp_profile, deadline)?;
        Ok(())
    }
}

pub(super) struct ReadbackPollBackoff {
    idle_polls: u32,
}

impl ReadbackPollBackoff {
    const SPIN_POLLS: u32 = 32;
    const MIN_PARK: Duration = Duration::from_micros(2);
    const MAX_PARK: Duration = Duration::from_micros(50);

    pub(super) fn new() -> Self {
        Self { idle_polls: 0 }
    }

    pub(super) fn idle(&mut self, deadline: Instant) {
        self.idle_polls = self.idle_polls.saturating_add(1);
        if self.idle_polls <= Self::SPIN_POLLS {
            std::hint::spin_loop();
            return;
        }
        if self.idle_polls <= Self::SPIN_POLLS * 2 {
            std::thread::yield_now();
            return;
        }
        let shift = (self.idle_polls - (Self::SPIN_POLLS * 2)).min(5);
        let park = Self::MIN_PARK
            .saturating_mul(1u32 << shift)
            .min(Self::MAX_PARK)
            .min(deadline.saturating_duration_since(Instant::now()));
        if !park.is_zero() {
            std::thread::park_timeout(park);
        }
    }
}
