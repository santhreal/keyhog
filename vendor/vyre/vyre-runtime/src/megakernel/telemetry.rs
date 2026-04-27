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
use std::collections::BTreeMap;

/// Decoded top-level ring slot state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingStatus {
    /// Slot is free.
    Empty,
    /// Slot is published and waiting for a worker.
    Published,
    /// Slot has been claimed by a worker.
    Claimed,
    /// Slot completed and can be recycled.
    Done,
    /// Slot is waiting for an asynchronous IO continuation.
    WaitIo,
    /// Slot yielded execution back to the scheduler.
    Yield,
    /// Slot is heavily contested and has been requeued.
    Requeue,
    /// Slot hit a hardware or software fault constraint.
    Fault,
    /// Unknown raw wire value.
    Unknown(u32),
}

impl RingStatus {
    #[must_use]
    fn from_raw(raw: u32) -> Self {
        match raw {
            slot::EMPTY => Self::Empty,
            slot::PUBLISHED => Self::Published,
            slot::CLAIMED => Self::Claimed,
            slot::DONE => Self::Done,
            slot::WAIT_IO => Self::WaitIo,
            slot::YIELD => Self::Yield,
            slot::REQUEUE => Self::Requeue,
            slot::FAULT => Self::Fault,
            other => Self::Unknown(other),
        }
    }

    /// Raw wire discriminant for sketching, replay, and compact telemetry.
    #[must_use]
    pub const fn raw(self) -> u32 {
        match self {
            Self::Empty => slot::EMPTY,
            Self::Published => slot::PUBLISHED,
            Self::Claimed => slot::CLAIMED,
            Self::Done => slot::DONE,
            Self::WaitIo => slot::WAIT_IO,
            Self::Yield => slot::YIELD,
            Self::Requeue => slot::REQUEUE,
            Self::Fault => slot::FAULT,
            Self::Unknown(raw) => raw,
        }
    }

    /// Whether this status still represents in-flight work rather than a
    /// terminal slot outcome.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(
            self,
            Self::Published | Self::Claimed | Self::WaitIo | Self::Yield | Self::Requeue
        )
    }
}

/// Snapshot of one ring slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingSlotSnapshot {
    /// Zero-based slot index.
    pub slot_idx: u32,
    /// Current state.
    pub status: RingStatus,
    /// Tenant id assigned to the slot.
    pub tenant_id: u32,
    /// Top-level opcode currently stored in the slot.
    pub opcode: u32,
    /// First three argument words, useful for quick debugging.
    pub args_prefix: [u32; 3],
}

/// Aggregated telemetry for one ticketed route window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowTelemetry {
    /// Stable ticket id encoded in `arg0`.
    pub ticket: u32,
    /// Tenant id shared by all emitted slots in this window.
    pub tenant_id: u32,
    /// Opcode shared by the window payload slots.
    pub opcode: u32,
    /// Number of required slots in the window.
    pub required_slots: u32,
    /// Number of lookahead slots in the window.
    pub lookahead_slots: u32,
    /// Number of slots currently published.
    pub published: u32,
    /// Number of slots currently claimed.
    pub claimed: u32,
    /// Number of slots completed.
    pub done: u32,
    /// Number of slots waiting for I/O.
    pub wait_io: u32,
    /// Number of yielded slots.
    pub yield_count: u32,
    /// Number of requeued slots.
    pub requeue: u32,
    /// Number of faulted slots.
    pub fault: u32,
}

impl WindowTelemetry {
    /// Whether this ticket still has unfinished work in the ring.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.published > 0
            || self.claimed > 0
            || self.wait_io > 0
            || self.yield_count > 0
            || self.requeue > 0
    }
}

/// Slot occupancy counts across the ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RingOccupancy {
    /// Number of empty slots.
    pub empty: u32,
    /// Number of published slots.
    pub published: u32,
    /// Number of claimed slots.
    pub claimed: u32,
    /// Number of done slots.
    pub done: u32,
    /// Number of slots waiting for IO.
    pub wait_io: u32,
    /// Number of slots yielded.
    pub yield_count: u32,
    /// Number of requeued slots.
    pub requeue: u32,
    /// Number of faulted slots.
    pub fault: u32,
    /// Number of slots with unrecognized raw status values.
    pub unknown: u32,
}

/// Structured view of the control buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlSnapshot {
    /// Shutdown flag.
    pub shutdown: bool,
    /// Total drained slots.
    pub done_count: u32,
    /// Epoch value (batch fences).
    pub epoch: u32,
    /// Non-zero opcode metrics.
    pub metrics: Vec<(u32, u32)>,
    /// Per-tenant fairness counters (cumulative).
    pub tenant_fairness: Vec<u32>,
    /// Per-priority fairness counters (cumulative).
    pub priority_fairness: Vec<u32>,
}

/// Fixed-depth Count-Min sketch for compact megakernel telemetry.
///
/// The layout is intentionally plain `Vec<u64>` plus `(depth, width)` so the
/// same shape can be mirrored by GPU control buffers later. Hashing is
/// deterministic and seed-indexed; no host randomness is involved, which keeps
/// replay and regression tests stable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountMinSketch {
    depth: usize,
    width: usize,
    counters: Vec<u64>,
}

impl CountMinSketch {
    /// Create a zeroed sketch with the requested dimensions.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when either dimension is zero or the counter
    /// table size overflows host address space.
    pub fn new(depth: usize, width: usize) -> Result<Self, PipelineError> {
        if depth == 0 || width == 0 {
            return Err(PipelineError::QueueFull {
                queue: "telemetry",
                fix: "Count-Min sketch depth and width must be non-zero",
            });
        }
        let len = depth.checked_mul(width).ok_or(PipelineError::QueueFull {
            queue: "telemetry",
            fix: "Count-Min sketch dimensions overflowed host address space; reduce depth or width",
        })?;
        Ok(Self {
            depth,
            width,
            counters: vec![0; len],
        })
    }

    /// Number of independent hash rows.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// Number of counters per hash row.
    #[must_use]
    pub const fn width(&self) -> usize {
        self.width
    }

    /// Raw row-major counters. Intended for readback, replay, and tests.
    #[must_use]
    pub fn counters(&self) -> &[u64] {
        &self.counters
    }

    /// Add `amount` to every row bucket selected for `key`.
    pub fn add(&mut self, key: u32, amount: u64) {
        if amount == 0 {
            return;
        }
        for row in 0..self.depth {
            let idx = self.bucket(row, key);
            self.counters[idx] = self.counters[idx].saturating_add(amount);
        }
    }

    /// Conservative point estimate for `key`.
    #[must_use]
    pub fn estimate(&self, key: u32) -> u64 {
        (0..self.depth)
            .map(|row| self.counters[self.bucket(row, key)])
            .min()
            .unwrap_or(0)
    }

    /// Merge another sketch with identical dimensions into this sketch.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] if the sketches have different shapes.
    pub fn merge(&mut self, other: &Self) -> Result<(), PipelineError> {
        if self.depth != other.depth || self.width != other.width {
            return Err(PipelineError::Backend(format!(
                "cannot merge Count-Min sketches with shapes {}x{} and {}x{}. Fix: construct telemetry sketches with the same dimensions.",
                self.depth, self.width, other.depth, other.width
            )));
        }
        for (left, right) in self.counters.iter_mut().zip(&other.counters) {
            *left = left.saturating_add(*right);
        }
        Ok(())
    }

    fn bucket(&self, row: usize, key: u32) -> usize {
        let hash = splitmix64(u64::from(key) ^ ((row as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)));
        row * self.width + (hash as usize % self.width)
    }
}

/// Compact sketch summary derived from a megakernel telemetry snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SketchTelemetry {
    /// Ring slots by opcode, regardless of terminal status.
    pub ring_opcode: CountMinSketch,
    /// Active ring slots by opcode.
    pub active_opcode: CountMinSketch,
    /// Ring slots by tenant id.
    pub tenant: CountMinSketch,
    /// Ring slots by raw status discriminant.
    pub status: CountMinSketch,
    /// Control-buffer dispatch metrics by opcode metric index.
    pub dispatch_metrics: CountMinSketch,
    /// Total decoded ring slots.
    pub total_slots: u64,
    /// Active decoded ring slots.
    pub active_slots: u64,
}

/// Combined host-visible telemetry for a megakernel run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingTelemetry {
    /// Decoded control-buffer snapshot.
    pub control: ControlSnapshot,
    /// Occupancy summary.
    pub occupancy: RingOccupancy,
    /// All decoded slots.
    pub slots: Vec<RingSlotSnapshot>,
    /// Decoded ticketed windows for any caller-specified window opcodes.
    pub windows: Vec<WindowTelemetry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct WindowAccumulator {
    tenant_id: u32,
    opcode: u32,
    required_slots: u32,
    lookahead_slots: u32,
    published: u32,
    claimed: u32,
    done: u32,
    wait_io: u32,
    yield_count: u32,
    requeue: u32,
    fault: u32,
}

fn read_word(buf: &[u8], word_idx: usize) -> Option<u32> {
    let off = word_idx.checked_mul(4)?;
    let end = off.checked_add(4)?;
    let bytes = buf.get(off..end)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn read_slot_word(buf: &[u8], slot_idx: u32, word_idx: u32) -> Option<u32> {
    let slot_words = SLOT_WORDS as usize;
    let base_word = (slot_idx as usize).checked_mul(slot_words)?;
    read_word(buf, base_word.checked_add(word_idx as usize)?)
}

impl ControlSnapshot {
    /// Decode a structured control-buffer view.
    #[must_use]
    pub fn decode(control_bytes: &[u8]) -> Self {
        let shutdown = read_word(control_bytes, control::SHUTDOWN as usize).unwrap_or(0) != 0;
        let done_count = read_word(control_bytes, control::DONE_COUNT as usize).unwrap_or(0);
        let epoch = read_word(control_bytes, control::EPOCH as usize).unwrap_or(0);
        let mut metrics = Vec::new();
        for i in 0..control::METRICS_SLOTS {
            let idx = (control::METRICS_BASE + i) as usize;
            let Some(count) = read_word(control_bytes, idx) else {
                break;
            };
            if count > 0 {
                metrics.push((i, count));
            }
        }
        Self {
            shutdown,
            done_count,
            epoch,
            metrics,
            tenant_fairness: (0..control::TENANT_FAIRNESS_SLOTS)
                .filter_map(|i| {
                    read_word(control_bytes, (control::TENANT_FAIRNESS_BASE + i) as usize)
                })
                .collect(),
            priority_fairness: (0..control::PRIORITY_FAIRNESS_SLOTS)
                .filter_map(|i| {
                    read_word(
                        control_bytes,
                        (control::PRIORITY_FAIRNESS_BASE + i) as usize,
                    )
                })
                .collect(),
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
        let control = ControlSnapshot::decode(control_bytes);
        let slot_count = ring_bytes.len() / ((SLOT_WORDS as usize) * 4);
        let mut occupancy = RingOccupancy::default();
        let mut slots = Vec::with_capacity(slot_count);
        let mut windows = BTreeMap::<(u32, u32), WindowAccumulator>::new();

        for slot_idx in 0..slot_count as u32 {
            let status_raw =
                read_slot_word(ring_bytes, slot_idx, STATUS_WORD).unwrap_or(slot::EMPTY);
            let status = RingStatus::from_raw(status_raw);
            match status {
                RingStatus::Empty => occupancy.empty += 1,
                RingStatus::Published => occupancy.published += 1,
                RingStatus::Claimed => occupancy.claimed += 1,
                RingStatus::Done => occupancy.done += 1,
                RingStatus::WaitIo => occupancy.wait_io += 1,
                RingStatus::Yield => occupancy.yield_count += 1,
                RingStatus::Requeue => occupancy.requeue += 1,
                RingStatus::Fault => occupancy.fault += 1,
                RingStatus::Unknown(_) => occupancy.unknown += 1,
            }
            let tenant_id = read_slot_word(ring_bytes, slot_idx, TENANT_WORD).unwrap_or(0);
            let opcode = read_slot_word(ring_bytes, slot_idx, OPCODE_WORD).unwrap_or(0);
            let args_prefix = [
                read_slot_word(ring_bytes, slot_idx, ARG0_WORD).unwrap_or(0),
                read_slot_word(ring_bytes, slot_idx, ARG0_WORD + 1).unwrap_or(0),
                read_slot_word(ring_bytes, slot_idx, ARG0_WORD + 2).unwrap_or(0),
            ];
            if window_opcodes.contains(&opcode) {
                let ticket = args_prefix[0];
                let class_tag = args_prefix[1];
                let entry = windows
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
            slots.push(RingSlotSnapshot {
                slot_idx,
                status,
                tenant_id,
                opcode,
                args_prefix,
            });
        }

        let windows = windows
            .into_iter()
            .map(|((ticket, _), acc)| WindowTelemetry {
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
            })
            .collect();

        Self {
            control,
            occupancy,
            slots,
            windows,
        }
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
        Ok(Self::decode_with_window_opcodes(
            control_bytes,
            ring_bytes,
            window_opcodes,
        ))
    }

    /// Active slots matching a given opcode.
    #[must_use]
    pub fn active_slots_for_opcode(&self, opcode: u32) -> Vec<&RingSlotSnapshot> {
        self.slots
            .iter()
            .filter(|slot| slot.opcode == opcode && slot.status.is_active())
            .collect()
    }

    /// Unfinished ticketed windows.
    #[must_use]
    pub fn active_windows(&self) -> Vec<&WindowTelemetry> {
        self.windows
            .iter()
            .filter(|window| window.is_active())
            .collect()
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

    /// Build compact sketches from the decoded telemetry snapshot.
    ///
    /// This is the host mirror of the telemetry shape a GPU-resident
    /// scheduler/fuzzer can maintain in control memory: hot opcodes, active
    /// work, tenant pressure, status pressure, and dispatch metrics all become
    /// bounded-size counters with deterministic replay semantics.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when sketch dimensions are invalid.
    pub fn sketch(&self, depth: usize, width: usize) -> Result<SketchTelemetry, PipelineError> {
        let mut ring_opcode = CountMinSketch::new(depth, width)?;
        let mut active_opcode = CountMinSketch::new(depth, width)?;
        let mut tenant = CountMinSketch::new(depth, width)?;
        let mut status = CountMinSketch::new(depth, width)?;
        let mut dispatch_metrics = CountMinSketch::new(depth, width)?;
        let mut active_slots = 0u64;

        for slot in &self.slots {
            ring_opcode.add(slot.opcode, 1);
            tenant.add(slot.tenant_id, 1);
            status.add(slot.status.raw(), 1);
            if slot.status.is_active() {
                active_slots = active_slots.saturating_add(1);
                active_opcode.add(slot.opcode, 1);
            }
        }

        for (opcode_idx, count) in &self.control.metrics {
            dispatch_metrics.add(*opcode_idx, u64::from(*count));
        }

        Ok(SketchTelemetry {
            ring_opcode,
            active_opcode,
            tenant,
            status,
            dispatch_metrics,
            total_slots: self.slots.len() as u64,
            active_slots,
        })
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

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::megakernel::descriptor::WindowClass;
    use crate::megakernel::protocol::opcode;
    use crate::megakernel::Megakernel;
    use crate::megakernel::{MegakernelExecutionMode, MegakernelLaunchRequest};

    #[test]
    fn decode_empty_ring_counts_slots() {
        let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
        let ring = Megakernel::try_encode_empty_ring(4).unwrap();
        let telemetry = RingTelemetry::decode(&control, &ring);
        assert_eq!(telemetry.occupancy.empty, 4);
        assert_eq!(telemetry.occupancy.published, 0);
        assert_eq!(telemetry.slots.len(), 4);
        assert!(telemetry.windows.is_empty());
    }

    #[test]
    fn strict_decode_rejects_trailing_partial_slot() {
        let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
        let mut ring = Megakernel::try_encode_empty_ring(1).unwrap();
        ring.push(0);
        let err = RingTelemetry::try_decode(&control, &ring)
            .expect_err("Fix: strict telemetry must reject malformed ring snapshots");
        assert!(matches!(err, PipelineError::Backend(_)));
    }

    #[test]
    fn strict_decode_rejects_misaligned_control_snapshot() {
        let mut control = Megakernel::try_encode_control(false, 1, 0).unwrap();
        control.push(0xFF);
        let ring = Megakernel::try_encode_empty_ring(1).unwrap();
        let err = RingTelemetry::try_decode(&control, &ring)
            .expect_err("Fix: strict telemetry must reject malformed control snapshots");
        assert!(matches!(err, PipelineError::Backend(_)));
    }

    #[test]
    fn decode_published_slot_reads_prefix() {
        let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
        let mut ring = Megakernel::try_encode_empty_ring(2).unwrap();
        Megakernel::publish_slot(&mut ring, 1, 9, opcode::ATOMIC_ADD, &[5, 7, 11]).unwrap();
        let telemetry = RingTelemetry::decode(&control, &ring);
        let slot = &telemetry.slots[1];
        assert_eq!(slot.status, RingStatus::Published);
        assert_eq!(slot.tenant_id, 9);
        assert_eq!(slot.opcode, opcode::ATOMIC_ADD);
        assert_eq!(slot.args_prefix, [5, 7, 11]);
    }

    #[test]
    fn decode_window_opcodes_groups_ticketed_slots() {
        let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
        let mut ring = Megakernel::try_encode_empty_ring(4).unwrap();
        let window_opcode = 0xF101;
        Megakernel::publish_slot(
            &mut ring,
            0,
            3,
            window_opcode,
            &[7, WindowClass::Required.into_wire(), 42],
        )
        .unwrap();
        Megakernel::publish_slot(
            &mut ring,
            1,
            3,
            window_opcode,
            &[7, WindowClass::Lookahead.into_wire(), 99],
        )
        .unwrap();
        Megakernel::publish_slot(
            &mut ring,
            2,
            3,
            window_opcode,
            &[7, WindowClass::Required.into_wire(), 123],
        )
        .unwrap();
        let telemetry =
            RingTelemetry::decode_with_window_opcodes(&control, &ring, &[window_opcode]);
        assert_eq!(telemetry.windows.len(), 1);
        let window = &telemetry.windows[0];
        assert_eq!(window.ticket, 7);
        assert_eq!(window.tenant_id, 3);
        assert_eq!(window.opcode, window_opcode);
        assert_eq!(window.required_slots, 2);
        assert_eq!(window.lookahead_slots, 1);
        assert_eq!(window.published, 3);
        assert!(window.is_active());
        assert_eq!(telemetry.active_windows().len(), 1);
        assert_eq!(telemetry.active_slots_for_opcode(window_opcode).len(), 3);
    }

    #[test]
    fn terminal_window_is_not_reported_as_active() {
        let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
        let mut ring = Megakernel::try_encode_empty_ring(2).unwrap();
        let window_opcode = 0xF101;
        Megakernel::publish_slot(
            &mut ring,
            0,
            3,
            window_opcode,
            &[9, WindowClass::Required.into_wire(), 42],
        )
        .unwrap();
        Megakernel::publish_slot(
            &mut ring,
            1,
            3,
            window_opcode,
            &[9, WindowClass::Lookahead.into_wire(), 99],
        )
        .unwrap();
        let mut mark_done = |slot_idx: usize| {
            let start = slot_idx * (SLOT_WORDS as usize) * 4 + (STATUS_WORD as usize) * 4;
            ring[start..start + 4].copy_from_slice(&slot::DONE.to_le_bytes());
        };
        mark_done(0);
        mark_done(1);
        let telemetry =
            RingTelemetry::decode_with_window_opcodes(&control, &ring, &[window_opcode]);
        assert_eq!(telemetry.windows.len(), 1);
        assert!(!telemetry.windows[0].is_active());
        assert!(telemetry.active_windows().is_empty());
        assert!(telemetry.active_slots_for_opcode(window_opcode).is_empty());
    }

    #[test]
    fn telemetry_recommendation_promotes_hot_opcodes_and_requeue_pressure() {
        let mut control = Megakernel::try_encode_control(false, 1, 0).unwrap();
        for opcode_idx in 0..8u32 {
            let off = ((control::METRICS_BASE + opcode_idx) as usize) * 4;
            control[off..off + 4].copy_from_slice(&1u32.to_le_bytes());
        }
        let mut ring = Megakernel::try_encode_empty_ring(4).unwrap();
        let status_off = (STATUS_WORD as usize) * 4;
        ring[status_off..status_off + 4].copy_from_slice(&slot::REQUEUE.to_le_bytes());
        let telemetry = RingTelemetry::decode(&control, &ring);
        let rec = telemetry
            .recommend_launch(MegakernelLaunchRequest::direct(4096, 64, 256))
            .expect("Fix: telemetry launch recommendation must accept valid limits");
        assert_eq!(rec.execution_mode, MegakernelExecutionMode::Jit);
        assert!(rec.promote_hot_opcodes);
        assert!(rec.age_priority_work);
        assert_eq!(telemetry.priority_accounting().requeue_count, 1);
    }

    #[test]
    fn metrics_and_observable_regions_remain_non_overlapping_in_snapshot() {
        let mut control = Megakernel::try_encode_control(false, 1, 4).unwrap();
        let metric_off = (control::METRICS_BASE as usize) * 4;
        control[metric_off..metric_off + 4].copy_from_slice(&0xAA55AA55u32.to_le_bytes());
        let observable_off = (control::OBSERVABLE_BASE as usize) * 4;
        control[observable_off..observable_off + 4].copy_from_slice(&0x11223344u32.to_le_bytes());

        let ring = Megakernel::try_encode_empty_ring(1).unwrap();
        let telemetry = RingTelemetry::decode(&control, &ring);
        assert!(
            telemetry.control.metrics.contains(&(0, 0xAA55AA55)),
            "metrics decoder must preserve metric slot 0 value"
        );
        assert_eq!(
            Megakernel::read_observable(&control, 0),
            0x11223344,
            "observable reads must not alias metric region words"
        );
    }
}
