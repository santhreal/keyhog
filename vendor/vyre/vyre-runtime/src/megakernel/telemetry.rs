//! Host-side telemetry decoders for the megakernel ring and control buffers.
//!
//! The runtime already exposes low-level helpers such as
//! `read_done_count`, `read_epoch`, and `read_metrics`. This module adds a
//! single structured snapshot surface useful for wrappers like VyreOffload.

use super::protocol::{
    control, slot, ARG0_WORD, OPCODE_WORD, SLOT_WORDS, STATUS_WORD, TENANT_WORD,
};
use super::scaling::{
    MegakernelLaunchPolicy, MegakernelLaunchRecommendation, MegakernelLaunchRequest,
    PriorityRequeueAccounting,
};
use crate::PipelineError;

mod sketch;
mod types;
pub use sketch::{CountMinSketch, SketchTelemetry, SketchTelemetryScratch};
use types::WindowAccumulator;
pub use types::{
    ControlSnapshot, MegakernelRuntimeCounters, MegakernelWatchdogSnapshot, RingOccupancy,
    RingSlotSnapshot, RingStatus, RingTelemetry, TelemetryDecodeScratch, WindowTelemetry,
};

fn read_word(buf: &[u8], word_idx: usize) -> Option<u32> {
    let off = word_idx.checked_mul(4)?;
    let end = off.checked_add(4)?;
    let bytes = buf.get(off..end)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn read_slot_chunk_word(slot_bytes: &[u8], word_idx: u32) -> u32 {
    let off = (word_idx as usize).saturating_mul(4);
    let end = off.saturating_add(4);
    slot_bytes
        .get(off..end)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0)
}

fn reserve_target_capacity<T>(out: &mut Vec<T>, target_capacity: usize) {
    if out.capacity() < target_capacity {
        out.reserve_exact(target_capacity);
    }
}

impl ControlSnapshot {
    /// Decode a structured control-buffer view.
    #[must_use]
    pub fn decode(control_bytes: &[u8]) -> Self {
        let mut out = Self::default();
        Self::decode_into(control_bytes, &mut out);
        out
    }

    /// Decode a structured control-buffer view into caller-owned storage.
    pub fn decode_into(control_bytes: &[u8], out: &mut Self) {
        out.shutdown = read_word(control_bytes, control::SHUTDOWN as usize).unwrap_or(0) != 0;
        out.done_count = read_word(control_bytes, control::DONE_COUNT as usize).unwrap_or(0);
        out.epoch = read_word(control_bytes, control::EPOCH as usize).unwrap_or(0);
        out.metrics.clear();
        reserve_target_capacity(&mut out.metrics, control::METRICS_SLOTS as usize);
        for i in 0..control::METRICS_SLOTS {
            let idx = (control::METRICS_BASE + i) as usize;
            let Some(count) = read_word(control_bytes, idx) else {
                break;
            };
            if count > 0 {
                out.metrics.push((i, count));
            }
        }
        out.tenant_fairness.clear();
        reserve_target_capacity(
            &mut out.tenant_fairness,
            control::TENANT_FAIRNESS_SLOTS as usize,
        );
        for i in 0..control::TENANT_FAIRNESS_SLOTS {
            let Some(value) =
                read_word(control_bytes, (control::TENANT_FAIRNESS_BASE + i) as usize)
            else {
                break;
            };
            out.tenant_fairness.push(value);
        }
        out.priority_fairness.clear();
        reserve_target_capacity(
            &mut out.priority_fairness,
            control::PRIORITY_FAIRNESS_SLOTS as usize,
        );
        for i in 0..control::PRIORITY_FAIRNESS_SLOTS {
            let Some(value) = read_word(
                control_bytes,
                (control::PRIORITY_FAIRNESS_BASE + i) as usize,
            ) else {
                break;
            };
            out.priority_fairness.push(value);
        }
    }
}

impl RingTelemetry {
    /// Decode the ring and control buffers into one structured snapshot.
    #[must_use]
    pub fn decode(control_bytes: &[u8], ring_bytes: &[u8]) -> Self {
        Self::decode_with_window_opcodes(control_bytes, ring_bytes, &[])
    }

    /// Strictly decode ring and control bytes after validating ABI alignment.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when buffers are truncated or not aligned to
    /// the megakernel wire protocol.
    pub fn try_decode(control_bytes: &[u8], ring_bytes: &[u8]) -> Result<Self, PipelineError> {
        Self::try_decode_with_window_opcodes(control_bytes, ring_bytes, &[])
    }

    /// Decode the ring and control buffers, additionally grouping any slots
    /// whose opcode is present in `window_opcodes` into ticketed route-window
    /// telemetry records.
    #[must_use]
    pub fn decode_with_window_opcodes(
        control_bytes: &[u8],
        ring_bytes: &[u8],
        window_opcodes: &[u32],
    ) -> Self {
        let mut out = Self::default();
        let mut scratch = TelemetryDecodeScratch::new();
        Self::decode_with_window_opcodes_into(
            control_bytes,
            ring_bytes,
            window_opcodes,
            &mut out,
            &mut scratch,
        );
        out
    }

    /// Decode the ring and control buffers into caller-owned telemetry and
    /// scratch storage.
    pub fn decode_with_window_opcodes_into(
        control_bytes: &[u8],
        ring_bytes: &[u8],
        window_opcodes: &[u32],
        out: &mut Self,
        scratch: &mut TelemetryDecodeScratch,
    ) {
        ControlSnapshot::decode_into(control_bytes, &mut out.control);
        let slot_count = ring_bytes.len() / ((SLOT_WORDS as usize) * 4);
        out.occupancy = RingOccupancy::default();
        out.slots.clear();
        reserve_target_capacity(&mut out.slots, slot_count);
        out.windows.clear();
        scratch.window_opcodes.clear();
        scratch.windows.clear();
        if !window_opcodes.is_empty() {
            reserve_target_capacity(&mut scratch.window_opcodes, window_opcodes.len());
            scratch
                .window_opcodes
                .extend(window_opcodes.iter().copied());
            scratch.window_opcodes.sort_unstable();
            scratch.window_opcodes.dedup();
            if scratch.windows.capacity() < slot_count {
                scratch
                    .windows
                    .reserve(slot_count - scratch.windows.capacity());
            }
        }
        let decode_windows = !scratch.window_opcodes.is_empty();

        let slot_byte_len = (SLOT_WORDS as usize) * 4;
        for (slot_idx, slot_bytes) in ring_bytes.chunks_exact(slot_byte_len).enumerate() {
            let slot_idx = slot_idx as u32;
            let status_raw = read_slot_chunk_word(slot_bytes, STATUS_WORD);
            let status = RingStatus::from_raw(status_raw);
            match status {
                RingStatus::Empty => out.occupancy.empty += 1,
                RingStatus::Published => out.occupancy.published += 1,
                RingStatus::Claimed => out.occupancy.claimed += 1,
                RingStatus::Done => out.occupancy.done += 1,
                RingStatus::WaitIo => out.occupancy.wait_io += 1,
                RingStatus::Yield => out.occupancy.yield_count += 1,
                RingStatus::Requeue => out.occupancy.requeue += 1,
                RingStatus::Fault => out.occupancy.fault += 1,
                RingStatus::Unknown(_) => out.occupancy.unknown += 1,
            }
            let tenant_id = read_slot_chunk_word(slot_bytes, TENANT_WORD);
            let opcode = read_slot_chunk_word(slot_bytes, OPCODE_WORD);
            let args_prefix = [
                read_slot_chunk_word(slot_bytes, ARG0_WORD),
                read_slot_chunk_word(slot_bytes, ARG0_WORD + 1),
                read_slot_chunk_word(slot_bytes, ARG0_WORD + 2),
            ];
            if decode_windows && scratch.window_opcodes.binary_search(&opcode).is_ok() {
                let ticket = args_prefix[0];
                let class_tag = args_prefix[1];
                let entry =
                    scratch
                        .windows
                        .entry((ticket, opcode))
                        .or_insert_with(|| WindowAccumulator {
                            tenant_id,
                            opcode,
                            ..WindowAccumulator::default()
                        });
                match class_tag {
                    0 => entry.required_slots += 1,
                    1 => entry.lookahead_slots += 1,
                    _ => {}
                }
                match status {
                    RingStatus::Published => entry.published += 1,
                    RingStatus::Claimed => entry.claimed += 1,
                    RingStatus::Done => entry.done += 1,
                    RingStatus::WaitIo => entry.wait_io += 1,
                    RingStatus::Yield => entry.yield_count += 1,
                    RingStatus::Requeue => entry.requeue += 1,
                    RingStatus::Fault => entry.fault += 1,
                    RingStatus::Empty | RingStatus::Unknown(_) => {}
                }
            }
            out.slots.push(RingSlotSnapshot {
                slot_idx,
                status,
                tenant_id,
                opcode,
                args_prefix,
            });
        }

        reserve_target_capacity(&mut out.windows, scratch.windows.len());
        for (&(ticket, _), acc) in &scratch.windows {
            out.windows.push(WindowTelemetry {
                ticket,
                tenant_id: acc.tenant_id,
                opcode: acc.opcode,
                required_slots: acc.required_slots,
                lookahead_slots: acc.lookahead_slots,
                published: acc.published,
                claimed: acc.claimed,
                done: acc.done,
                wait_io: acc.wait_io,
                yield_count: acc.yield_count,
                requeue: acc.requeue,
                fault: acc.fault,
            });
        }
        out.windows
            .sort_unstable_by_key(|window| (window.ticket, window.opcode));
    }

    /// Strictly decode ring/control bytes and group selected window opcodes.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when buffers are truncated or not aligned to
    /// the megakernel wire protocol.
    pub fn try_decode_with_window_opcodes(
        control_bytes: &[u8],
        ring_bytes: &[u8],
        window_opcodes: &[u32],
    ) -> Result<Self, PipelineError> {
        validate_telemetry_buffers(control_bytes, ring_bytes)?;
        Ok(Self::decode_with_window_opcodes(
            control_bytes,
            ring_bytes,
            window_opcodes,
        ))
    }

    /// Strictly decode ring/control bytes into caller-owned telemetry and
    /// scratch storage.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when buffers are truncated or not aligned to
    /// the megakernel wire protocol.
    pub fn try_decode_with_window_opcodes_into(
        control_bytes: &[u8],
        ring_bytes: &[u8],
        window_opcodes: &[u32],
        out: &mut Self,
        scratch: &mut TelemetryDecodeScratch,
    ) -> Result<(), PipelineError> {
        validate_telemetry_buffers(control_bytes, ring_bytes)?;
        Self::decode_with_window_opcodes_into(
            control_bytes,
            ring_bytes,
            window_opcodes,
            out,
            scratch,
        );
        Ok(())
    }

    /// Active slots matching a given opcode.
    #[must_use]
    pub fn active_slots_for_opcode(&self, opcode: u32) -> Vec<&RingSlotSnapshot> {
        let mut out = Vec::with_capacity(self.slots.len());
        self.active_slots_for_opcode_into(opcode, &mut out);
        out
    }

    /// Active slots matching a given opcode into caller-owned storage.
    pub fn active_slots_for_opcode_into<'a>(
        &'a self,
        opcode: u32,
        out: &mut Vec<&'a RingSlotSnapshot>,
    ) {
        out.clear();
        reserve_target_capacity(out, self.slots.len());
        self.slots
            .iter()
            .filter(|slot| slot.opcode == opcode && slot.status.is_active())
            .for_each(|slot| out.push(slot));
    }

    /// Unfinished ticketed windows.
    #[must_use]
    pub fn active_windows(&self) -> Vec<&WindowTelemetry> {
        let mut out = Vec::with_capacity(self.windows.len());
        self.active_windows_into(&mut out);
        out
    }

    /// Unfinished ticketed windows into caller-owned storage.
    pub fn active_windows_into<'a>(&'a self, out: &mut Vec<&'a WindowTelemetry>) {
        out.clear();
        reserve_target_capacity(out, self.windows.len());
        self.windows
            .iter()
            .filter(|window| window.is_active())
            .for_each(|window| out.push(window));
    }

    /// Summarize priority requeue/aging pressure visible in the ring snapshot.
    #[must_use]
    pub fn priority_accounting(&self) -> PriorityRequeueAccounting {
        PriorityRequeueAccounting {
            requeue_count: u64::from(self.occupancy.requeue),
            aged_promotions: 0,
            max_priority_age: 0,
        }
    }

    /// Aggregate queue, idle, fairness, and drain counters into one cheap
    /// runtime snapshot for SRE dashboards and launch-policy feedback.
    #[must_use]
    pub fn runtime_counters(&self) -> MegakernelRuntimeCounters {
        let total_slots = self.occupancy.total_slots();
        let queue_depth = self.occupancy.queue_depth();
        let gpu_idle_slots = self.occupancy.empty;
        let gpu_idle_ppm = if total_slots == 0 {
            0
        } else {
            ((u64::from(gpu_idle_slots) * 1_000_000) / u64::from(total_slots)) as u32
        };
        let tenant_fairness_total = self
            .control
            .tenant_fairness
            .iter()
            .fold(0u64, |acc, &count| acc.saturating_add(u64::from(count)));
        let priority_fairness_total = self
            .control
            .priority_fairness
            .iter()
            .fold(0u64, |acc, &count| acc.saturating_add(u64::from(count)));
        let tenant_fairness_skew = fairness_skew(&self.control.tenant_fairness);
        MegakernelRuntimeCounters {
            total_slots,
            queue_depth,
            gpu_idle_slots,
            gpu_idle_ppm,
            drained_slots: self.control.done_count,
            unreclaimed_done_slots: self.occupancy.done,
            tenant_fairness_total,
            tenant_fairness_skew,
            priority_fairness_total,
            requeue_slots: self.occupancy.requeue,
            fault_slots: self.occupancy.fault,
        }
    }

    /// Derive persistent-kernel health from two snapshots without polling the
    /// device or synchronizing with the GPU.
    #[must_use]
    pub fn health_since(&self, previous: &RingTelemetry) -> MegakernelWatchdogSnapshot {
        let counters = self.runtime_counters();
        let done_delta = self
            .control
            .done_count
            .saturating_sub(previous.control.done_count);
        let suspected_stall =
            counters.queue_depth > 0 && done_delta == 0 && counters.fault_slots == 0;
        MegakernelWatchdogSnapshot {
            done_delta,
            queue_depth: counters.queue_depth,
            fault_slots: counters.fault_slots,
            requeue_slots: counters.requeue_slots,
            gpu_idle_ppm: counters.gpu_idle_ppm,
            suspected_stall,
        }
    }

    /// Feed telemetry into the shared launch policy.
    ///
    /// # Errors
    ///
    /// Returns a backend error when the supplied adapter limits are malformed.
    pub fn recommend_launch(
        &self,
        mut request: MegakernelLaunchRequest,
    ) -> Result<MegakernelLaunchRecommendation, vyre_driver::BackendError> {
        request.hot_opcode_count = self
            .control
            .metrics
            .iter()
            .filter(|(_, count)| *count > 0)
            .count()
            .min(u32::MAX as usize) as u32;
        request.hot_window_count = self
            .windows
            .iter()
            .filter(|window| window.required_slots.saturating_add(window.lookahead_slots) >= 4)
            .count()
            .min(u32::MAX as usize) as u32;
        request.requeue_count = request
            .requeue_count
            .saturating_add(u64::from(self.occupancy.requeue));
        MegakernelLaunchPolicy::standard().recommend(request)
    }
}

fn validate_telemetry_buffers(
    control_bytes: &[u8],
    ring_bytes: &[u8],
) -> Result<(), PipelineError> {
    let min_control = super::protocol::control_byte_len(0).ok_or_else(|| {
        PipelineError::Backend(
            "megakernel control length overflowed usize. Fix: keep protocol constants bounded."
                .to_string(),
        )
    })?;
    if control_bytes.len() < min_control || control_bytes.len() % 4 != 0 {
        return Err(PipelineError::Backend(format!(
            "megakernel control snapshot has {} bytes, expected at least {min_control} and 4-byte alignment. Fix: capture the full control buffer.",
            control_bytes.len()
        )));
    }
    let slot_bytes = (SLOT_WORDS as usize)
        .checked_mul(4)
        .ok_or(PipelineError::QueueFull {
            queue: "telemetry",
            fix: "slot byte width overflowed usize; keep SLOT_WORDS within the u32 ABI",
        })?;
    if ring_bytes.len() % slot_bytes != 0 {
        return Err(PipelineError::Backend(format!(
            "megakernel ring snapshot has {} bytes, not a multiple of slot size {slot_bytes}. Fix: capture whole ring slots.",
            ring_bytes.len()
        )));
    }
    Ok(())
}

fn fairness_skew(counters: &[u32]) -> u32 {
    let mut min_nonzero = u32::MAX;
    let mut max = 0u32;
    for &count in counters {
        if count != 0 {
            min_nonzero = min_nonzero.min(count);
            max = max.max(count);
        }
    }
    if min_nonzero == u32::MAX {
        0
    } else {
        max.saturating_sub(min_nonzero)
    }
}

#[cfg(test)]
    mod tests {
        include!("telemetry_tests.rs");
    }
