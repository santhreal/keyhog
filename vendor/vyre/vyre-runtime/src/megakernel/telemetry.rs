//! Host-side telemetry decoders for the megakernel ring and control buffers.
//!
//! The runtime already exposes low-level helpers such as
//! `read_done_count`, `read_epoch`, and `read_metrics`. This module adds a
//! single structured snapshot surface useful for wrappers like VyreOffload.

use super::protocol::{control, slot, ARG0_WORD, OPCODE_WORD, STATUS_WORD, TENANT_WORD};
use super::scaling::{
    MegakernelLaunchPolicy, MegakernelLaunchRecommendation, MegakernelLaunchRequest,
    PriorityRequeueAccounting,
};
use super::staging_reserve::{
    reserve_hash_map_capacity, reserve_vec_capacity as reserve_target_capacity,
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

const SLOT_WORDS_USIZE: usize = 16;

fn read_word(buf: &[u8], word_idx: usize) -> Option<u32> {
    let off = word_idx.checked_mul(4)?;
    let end = off.checked_add(4)?;
    let bytes = buf.get(off..end)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn read_slot_chunk_word_exact(slot_bytes: &[u8], word_idx: u32) -> u32 {
    let off = telemetry_u32_to_usize(word_idx, "slot word index")
        .checked_mul(4)
        .unwrap_or_else(|| {
            panic!(
                "megakernel telemetry slot word byte offset overflowed usize. Fix: keep slot word indices within host address space."
            )
        });
    u32::from_le_bytes([
        slot_bytes[off],
        slot_bytes[off + 1],
        slot_bytes[off + 2],
        slot_bytes[off + 3],
    ])
}

fn is_sorted_unique_u32(values: &[u32]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

impl ControlSnapshot {
    /// Decode a structured control-buffer view.
    #[must_use]
    pub fn decode(control_bytes: &[u8]) -> Self {
        let mut out = Self::default();
        Self::try_decode_into(control_bytes, &mut out).unwrap_or_else(|source| {
            panic!(
                "megakernel control telemetry decode failed: {source}. Fix: capture the full control buffer before telemetry decode."
            )
        });
        out
    }

    /// Decode a structured control-buffer view into caller-owned storage.
    pub fn decode_into(control_bytes: &[u8], out: &mut Self) {
        Self::try_decode_into(control_bytes, out).unwrap_or_else(|source| {
            panic!(
                "megakernel control telemetry decode failed: {source}. Fix: capture the full control buffer before telemetry decode."
            )
        });
    }

    /// Strictly decode a structured control-buffer view.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when any fixed control word is missing from
    /// the control snapshot.
    pub fn try_decode_into(control_bytes: &[u8], out: &mut Self) -> Result<(), PipelineError> {
        validate_control_snapshot(control_bytes)?;
        out.shutdown =
            read_required_control_word(control_bytes, control_word_index(control::SHUTDOWN)?)? != 0;
        out.done_count =
            read_required_control_word(control_bytes, control_word_index(control::DONE_COUNT)?)?;
        out.epoch = read_required_control_word(control_bytes, control_word_index(control::EPOCH)?)?;
        out.metrics.clear();
        reserve_target_capacity(
            &mut out.metrics,
            telemetry_u32_to_usize(control::METRICS_SLOTS, "metrics slot count"),
            "metrics",
        )?;
        for i in 0..control::METRICS_SLOTS {
            let count = read_required_control_word(
                control_bytes,
                control_offset_index(control::METRICS_BASE, i)?,
            )?;
            if count > 0 {
                out.metrics.push((i, count));
            }
        }
        out.tenant_fairness.clear();
        reserve_target_capacity(
            &mut out.tenant_fairness,
            telemetry_u32_to_usize(control::TENANT_FAIRNESS_SLOTS, "tenant fairness slot count"),
            "tenant fairness",
        )?;
        for i in 0..control::TENANT_FAIRNESS_SLOTS {
            out.tenant_fairness.push(read_required_control_word(
                control_bytes,
                control_offset_index(control::TENANT_FAIRNESS_BASE, i)?,
            )?);
        }
        out.priority_fairness.clear();
        reserve_target_capacity(
            &mut out.priority_fairness,
            telemetry_u32_to_usize(
                control::PRIORITY_FAIRNESS_SLOTS,
                "priority fairness slot count",
            ),
            "priority fairness",
        )?;
        for i in 0..control::PRIORITY_FAIRNESS_SLOTS {
            out.priority_fairness.push(read_required_control_word(
                control_bytes,
                control_offset_index(control::PRIORITY_FAIRNESS_BASE, i)?,
            )?);
        }
        Ok(())
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
        validate_telemetry_buffers(control_bytes, ring_bytes).unwrap_or_else(|source| {
            panic!(
                "megakernel ring telemetry decode failed: {source}. Fix: capture full control and whole ring-slot buffers before telemetry decode."
            )
        });
        let mut out = Self::default();
        let mut scratch = TelemetryDecodeScratch::new();
        Self::try_decode_with_window_opcodes_into_unchecked(
            control_bytes,
            ring_bytes,
            window_opcodes,
            &mut out,
            &mut scratch,
        )
        .unwrap_or_else(|source| {
            panic!(
                "megakernel ring telemetry decode failed: {source}. Fix: capture full control and whole ring-slot buffers before telemetry decode."
            )
        });
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
        validate_telemetry_buffers(control_bytes, ring_bytes).unwrap_or_else(|source| {
            panic!(
                "megakernel ring telemetry decode failed: {source}. Fix: capture full control and whole ring-slot buffers before telemetry decode."
            )
        });
        Self::try_decode_with_window_opcodes_into_unchecked(
            control_bytes,
            ring_bytes,
            window_opcodes,
            out,
            scratch,
        )
        .unwrap_or_else(|source| {
            panic!(
                "megakernel ring telemetry decode failed: {source}. Fix: capture full control and whole ring-slot buffers before telemetry decode."
            )
        });
    }

    fn try_decode_with_window_opcodes_into_unchecked(
        control_bytes: &[u8],
        ring_bytes: &[u8],
        window_opcodes: &[u32],
        out: &mut Self,
        scratch: &mut TelemetryDecodeScratch,
    ) -> Result<(), PipelineError> {
        enum WindowOpcodeMatcher<'a> {
            None,
            Single(u32),
            DenseBitmap(u128),
            SmallSlice(&'a [u32]),
            LargeSlice(&'a [u32]),
        }

        ControlSnapshot::try_decode_into(control_bytes, &mut out.control)?;
        let slot_count = ring_bytes.len() / slot_byte_len();
        out.occupancy = RingOccupancy::default();
        out.slots.clear();
        reserve_target_capacity(&mut out.slots, slot_count, "ring slots")?;
        out.windows.clear();
        scratch.window_opcodes.clear();
        scratch.windows.clear();
        let window_opcode_lookup = if window_opcodes.is_empty() {
            &[][..]
        } else if is_sorted_unique_u32(window_opcodes) {
            window_opcodes
        } else {
            reserve_target_capacity(
                &mut scratch.window_opcodes,
                window_opcodes.len(),
                "window opcode scratch",
            )?;
            scratch.window_opcodes.extend_from_slice(window_opcodes);
            scratch.window_opcodes.sort_unstable();
            scratch.window_opcodes.dedup();
            scratch.window_opcodes.as_slice()
        };
        let window_opcode_matcher = match window_opcode_lookup {
            [] => WindowOpcodeMatcher::None,
            [opcode] => WindowOpcodeMatcher::Single(*opcode),
            opcodes if opcodes.len() > 1 && opcodes.iter().all(|opcode| *opcode < 128) => {
                let bitmap = opcodes
                    .iter()
                    .fold(0_u128, |acc, &opcode| acc | (1_u128 << opcode));
                WindowOpcodeMatcher::DenseBitmap(bitmap)
            }
            opcodes if opcodes.len() <= 8 => WindowOpcodeMatcher::SmallSlice(opcodes),
            opcodes => WindowOpcodeMatcher::LargeSlice(opcodes),
        };
        if !matches!(window_opcode_matcher, WindowOpcodeMatcher::None) {
            reserve_hash_map_capacity(
                &mut scratch.windows,
                slot_count,
                "window accumulator scratch",
            )?;
        }
        let decode_windows = !matches!(window_opcode_matcher, WindowOpcodeMatcher::None);

        let slot_byte_len = slot_byte_len();
        for (slot_idx, slot_bytes) in ring_bytes.chunks_exact(slot_byte_len).enumerate() {
            let slot_idx = u32::try_from(slot_idx).unwrap_or_else(|source| {
                panic!(
                    "megakernel telemetry slot index cannot fit u32: {source}. Fix: shard ring snapshots before host decode."
                )
            });
            let status_raw = read_slot_chunk_word_exact(slot_bytes, STATUS_WORD);
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
            let tenant_id = read_slot_chunk_word_exact(slot_bytes, TENANT_WORD);
            let opcode = read_slot_chunk_word_exact(slot_bytes, OPCODE_WORD);
            let args_prefix = [
                read_slot_chunk_word_exact(slot_bytes, ARG0_WORD),
                read_slot_chunk_word_exact(slot_bytes, ARG0_WORD + 1),
                read_slot_chunk_word_exact(slot_bytes, ARG0_WORD + 2),
            ];
            let is_window_opcode = match window_opcode_matcher {
                WindowOpcodeMatcher::None => false,
                WindowOpcodeMatcher::Single(expected) => opcode == expected,
                WindowOpcodeMatcher::DenseBitmap(bitmap) => {
                    opcode < 128 && ((bitmap >> opcode) & 1) == 1
                }
                WindowOpcodeMatcher::SmallSlice(window_opcodes) => window_opcodes.contains(&opcode),
                WindowOpcodeMatcher::LargeSlice(window_opcodes) => {
                    window_opcodes.binary_search(&opcode).is_ok()
                }
            };
            if decode_windows && is_window_opcode {
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

        reserve_target_capacity(&mut out.windows, scratch.windows.len(), "window output")?;
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
        Ok(())
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
        let mut out = Self::default();
        let mut scratch = TelemetryDecodeScratch::new();
        Self::try_decode_with_window_opcodes_into_unchecked(
            control_bytes,
            ring_bytes,
            window_opcodes,
            &mut out,
            &mut scratch,
        )?;
        Ok(out)
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
        Self::try_decode_with_window_opcodes_into_unchecked(
            control_bytes,
            ring_bytes,
            window_opcodes,
            out,
            scratch,
        )?;
        Ok(())
    }

    /// Active slots matching a given opcode.
    #[must_use]
    pub fn active_slots_for_opcode(&self, opcode: u32) -> Vec<&RingSlotSnapshot> {
        self.try_active_slots_for_opcode(opcode).unwrap_or_else(|source| {
            panic!(
                "megakernel active-slot telemetry query failed: {source}. Fix: decode into caller-owned reusable slot scratch."
            )
        })
    }

    /// Active slots matching a given opcode with fallible output staging.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when output storage cannot be reserved.
    pub fn try_active_slots_for_opcode(
        &self,
        opcode: u32,
    ) -> Result<Vec<&RingSlotSnapshot>, PipelineError> {
        let mut out = Vec::new();
        self.try_active_slots_for_opcode_into(opcode, &mut out)?;
        Ok(out)
    }

    /// Active slots matching a given opcode as an iterator.
    pub fn active_slots_for_opcode_iter(
        &self,
        opcode: u32,
    ) -> impl Iterator<Item = &RingSlotSnapshot> {
        self.slots
            .iter()
            .filter(move |slot| slot.opcode == opcode && slot.status.is_active())
    }

    /// Active slots matching a given opcode into caller-owned storage.
    pub fn active_slots_for_opcode_into<'a>(
        &'a self,
        opcode: u32,
        out: &mut Vec<&'a RingSlotSnapshot>,
    ) {
        self.try_active_slots_for_opcode_into(opcode, out)
            .unwrap_or_else(|source| {
                panic!(
                    "megakernel active-slot telemetry query failed: {source}. Fix: decode into caller-owned reusable slot scratch."
                )
            });
    }

    /// Active slots matching a given opcode into caller-owned storage.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when output storage cannot be reserved.
    pub fn try_active_slots_for_opcode_into<'a>(
        &'a self,
        opcode: u32,
        out: &mut Vec<&'a RingSlotSnapshot>,
    ) -> Result<(), PipelineError> {
        out.clear();
        reserve_target_capacity(out, self.slots.len(), "active slot output")?;
        self.slots
            .iter()
            .filter(|slot| slot.opcode == opcode && slot.status.is_active())
            .for_each(|slot| out.push(slot));
        Ok(())
    }

    /// Unfinished ticketed windows.
    #[must_use]
    pub fn active_windows(&self) -> Vec<&WindowTelemetry> {
        self.try_active_windows().unwrap_or_else(|source| {
            panic!(
                "megakernel active-window telemetry query failed: {source}. Fix: decode into caller-owned reusable window scratch."
            )
        })
    }

    /// Unfinished ticketed windows with fallible output staging.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when output storage cannot be reserved.
    pub fn try_active_windows(&self) -> Result<Vec<&WindowTelemetry>, PipelineError> {
        let mut out = Vec::new();
        self.try_active_windows_into(&mut out)?;
        Ok(out)
    }

    /// Unfinished ticketed windows into caller-owned storage.
    pub fn active_windows_into<'a>(&'a self, out: &mut Vec<&'a WindowTelemetry>) {
        self.try_active_windows_into(out).unwrap_or_else(|source| {
            panic!(
                "megakernel active-window telemetry query failed: {source}. Fix: decode into caller-owned reusable window scratch."
            )
        });
    }

    /// Unfinished ticketed windows into caller-owned storage.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when output storage cannot be reserved.
    pub fn try_active_windows_into<'a>(
        &'a self,
        out: &mut Vec<&'a WindowTelemetry>,
    ) -> Result<(), PipelineError> {
        out.clear();
        reserve_target_capacity(out, self.windows.len(), "active window output")?;
        self.windows
            .iter()
            .filter(|window| window.is_active())
            .for_each(|window| out.push(window));
        Ok(())
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
            let raw_idle_ppm = (u64::from(gpu_idle_slots) * 1_000_000) / u64::from(total_slots);
            raw_idle_ppm.min(1_000_000) as u32
        };
        let frontier_density_bps = density_bps(queue_depth, total_slots);
        let active_slots = total_slots.saturating_sub(gpu_idle_slots);
        let occupancy_proxy_bps = density_bps(active_slots, total_slots);
        let tenant_fairness_total = self
            .control
            .tenant_fairness
            .iter()
            .try_fold(0u64, |acc, &count| acc.checked_add(u64::from(count)))
            .unwrap_or_else(|| {
                panic!(
                    "megakernel tenant fairness total overflowed u64. Fix: shard tenant counters before telemetry aggregation."
                )
            });
        let priority_fairness_total = self
            .control
            .priority_fairness
            .iter()
            .try_fold(0u64, |acc, &count| acc.checked_add(u64::from(count)))
            .unwrap_or_else(|| {
                panic!(
                    "megakernel priority fairness total overflowed u64. Fix: shard priority counters before telemetry aggregation."
                )
            });
        let tenant_fairness_skew = fairness_skew(&self.control.tenant_fairness);
        MegakernelRuntimeCounters {
            total_slots,
            queue_depth,
            gpu_idle_slots,
            gpu_idle_ppm,
            frontier_density_bps,
            occupancy_proxy_bps,
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
            .checked_sub(previous.control.done_count)
            .unwrap_or_else(|| {
                panic!(
                    "megakernel done counter moved backwards from {} to {}. Fix: treat counter reset/wrap as a new telemetry epoch.",
                    previous.control.done_count,
                    self.control.done_count
                )
            });
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
        let counters = self.runtime_counters();
        if request.graph_node_count == 0 {
            request.graph_node_count = counters.total_slots;
        }
        if request.graph_edge_count == 0 {
            request.graph_edge_count = counters.queue_depth;
        }
        if request.frontier_density_bps == 0 {
            request.frontier_density_bps = counters.frontier_density_bps;
        }
        request.hot_opcode_count = self
            .control
            .metrics
            .iter()
            .filter(|(_, count)| *count > 0)
            .count()
            .try_into()
            .unwrap_or_else(|source| {
                panic!(
                    "megakernel hot opcode count cannot fit u32: {source}. Fix: cap metrics slots at the protocol boundary."
                )
            });
        request.hot_window_count = self
            .windows
            .iter()
            .filter(|window| {
                window
                    .required_slots
                    .checked_add(window.lookahead_slots)
                    .unwrap_or_else(|| {
                        panic!(
                            "megakernel route-window slot demand overflowed u32. Fix: shard route windows before telemetry aggregation."
                        )
                    })
                    >= 4
            })
            .count()
            .try_into()
            .unwrap_or_else(|source| {
                panic!(
                    "megakernel hot window count cannot fit u32: {source}. Fix: shard telemetry windows before launch recommendation."
                )
            });
        request.requeue_count = request
            .requeue_count
            .checked_add(u64::from(self.occupancy.requeue))
            .unwrap_or_else(|| {
                panic!(
                    "megakernel requeue count overflowed u64. Fix: shard telemetry windows before launch recommendation."
                )
            });
        MegakernelLaunchPolicy::standard().recommend(request)
    }
}


fn read_required_control_word(control_bytes: &[u8], word_idx: usize) -> Result<u32, PipelineError> {
    read_word(control_bytes, word_idx).ok_or_else(|| {
        PipelineError::Backend(format!(
            "megakernel control snapshot is missing required word {word_idx}. Fix: capture the full control buffer before telemetry decode."
        ))
    })
}

fn density_bps(numerator: u32, denominator: u32) -> u16 {
    if denominator == 0 {
        return 0;
    }
    let bps = (u64::from(numerator) * 10_000) / u64::from(denominator);
    u16::try_from(bps.min(u64::from(u16::MAX))).unwrap_or_else(|source| {
        panic!(
            "megakernel density bps cannot fit u16 after clamp: {source}. Fix: repair density accounting."
        )
    })
}

fn validate_telemetry_buffers(
    control_bytes: &[u8],
    ring_bytes: &[u8],
) -> Result<(), PipelineError> {
    validate_control_snapshot(control_bytes)?;
    let slot_bytes = slot_byte_len();
    if ring_bytes.len() % slot_bytes != 0 {
        return Err(PipelineError::Backend(format!(
            "megakernel ring snapshot has {} bytes, not a multiple of slot size {slot_bytes}. Fix: capture whole ring slots.",
            ring_bytes.len()
        )));
    }
    let slot_count = ring_bytes.len() / slot_bytes;
    if u32::try_from(slot_count).is_err() {
        return Err(PipelineError::Backend(format!(
            "megakernel ring snapshot has {slot_count} slots, above the u32 telemetry ABI. Fix: shard ring snapshots before host decode."
        )));
    }
    Ok(())
}

fn validate_control_snapshot(control_bytes: &[u8]) -> Result<(), PipelineError> {
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
    Ok(())
}

fn slot_byte_len() -> usize {
    SLOT_WORDS_USIZE.checked_mul(4).unwrap_or_else(|| {
        panic!(
            "megakernel telemetry slot byte width overflowed usize. Fix: keep SLOT_WORDS within host address space."
        )
    })
}

fn telemetry_u32_to_usize(value: u32, label: &'static str) -> usize {
    usize::try_from(value).unwrap_or_else(|source| {
        panic!(
            "megakernel telemetry {label} value {value} cannot fit usize: {source}. Fix: shard telemetry buffers before host decode."
        )
    })
}

fn control_word_index(word: u32) -> Result<usize, PipelineError> {
    usize::try_from(word).map_err(|source| {
        PipelineError::Backend(format!(
            "megakernel control word index {word} cannot fit usize: {source}. Fix: keep control ABI words within host address space."
        ))
    })
}

fn control_offset_index(base: u32, offset: u32) -> Result<usize, PipelineError> {
    let word = base.checked_add(offset).ok_or_else(|| {
        PipelineError::Backend(
            "megakernel control word offset overflowed u32. Fix: shard telemetry arrays before host decode."
                .to_string(),
        )
    })?;
    control_word_index(word)
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
        max.checked_sub(min_nonzero).unwrap_or_else(|| {
            panic!(
                "megakernel fairness skew saw max {max} below min_nonzero {min_nonzero}. Fix: reject malformed fairness counters before telemetry aggregation."
            )
        })
    }
}

#[cfg(test)]
mod tests {
    include!("telemetry_tests.rs");
}

