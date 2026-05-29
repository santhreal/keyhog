//! Async readback ring (Innovation I.5).
//!
//! Blocking readback submits a copy + device.poll(Wait) that stalls
//! the submit queue. Under high dispatch rate this ruins latency and
//! throughput  -  the GPU goes idle while the CPU waits.
//!
//! The readback ring threads N staging buffers. Dispatch \`i\` writes
//! to \`ring[i % N]\`; the copy submits immediately and readback
//! happens asynchronously via \`map_async\`. Dispatch \`i+1\` runs in
//! parallel with readback \`i\`'s copy.

use crossbeam_channel::Receiver;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use rustc_hash::FxHasher;
use std::hash::BuildHasherDefault;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use vyre_driver::accounting::{atomic_max_u64, rebasing_atomic_next_u64};
use vyre_driver::backend::BackendError;

use crate::staging_reserve::reserve_backend_vec;

const MIN_RING_SIZE: usize = 2;
const MAX_RING_SIZE: usize = 256;
const DEFAULT_RING_SLOTS: usize = 256;
const RING_CAPACITY_GRANULARITY: u64 = 4096;
const SLOT_FREE: u8 = 0;
const SLOT_PENDING: u8 = 1;
const SLOT_READY: u8 = 2;
const SLOT_ERROR: u8 = 3;

/// Result type produced by one `map_async` callback.
pub type MapResult = Result<(), wgpu::BufferAsyncError>;

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
        rebasing_atomic_next_u64(
            &self.dispatches,
            0,
            Ordering::Relaxed,
            Ordering::Relaxed,
            Ordering::Relaxed,
            |_, _| {
                tracing::error!(
                    "readback ring dispatch counter reached u64::MAX and was rebased to zero. Fix: shard readback rings or scrape counters before wrap."
                );
            },
        )
    }

    /// Record a stall.
    pub fn record_stall(&self) {
        rebasing_atomic_next_u64(
            &self.readback_stalls,
            0,
            Ordering::Relaxed,
            Ordering::Relaxed,
            Ordering::Relaxed,
            |_, _| {
                tracing::error!(
                    "readback ring stall counter reached u64::MAX and was rebased to zero. Fix: shard readback rings or scrape counters before wrap."
                );
            },
        );
    }

    /// Update the peak-in-flight watermark.
    pub fn update_peak(&self, current: u64) {
        atomic_max_u64(&self.peak_inflight, current, Ordering::AcqRel);
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
    byte_len: AtomicU64,
    mapped_len: AtomicU64,
    capacity: u64,
}

/// Submitted copy ticket for one readback-ring slot.
pub struct ReadbackTicket {
    idx: usize,
    byte_len: u64,
    mapped_len: u64,
}

/// Size-classed collection of readback rings for direct dispatch.
pub struct ReadbackRingSet {
    rings: DashMap<u64, Arc<ReadbackRing>, BuildHasherDefault<FxHasher>>,
    slots_per_ring: usize,
}

impl Default for ReadbackRingSet {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadbackRingSet {
    /// Construct an empty ring set using the default slot count.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rings: DashMap::with_hasher(BuildHasherDefault::<FxHasher>::default()),
            slots_per_ring: readback_ring_slots_from_env(),
        }
    }

    /// Construct an empty ring set from a raw slot-count setting.
    ///
    /// Passing `None` uses the production default. This keeps test and embedded
    /// callers off process-global environment mutation while preserving the same
    /// parser and clamping semantics as [`Self::new`].
    #[must_use]
    pub fn with_requested_slots(raw_slots: Option<&str>) -> Self {
        Self {
            rings: DashMap::with_hasher(BuildHasherDefault::<FxHasher>::default()),
            slots_per_ring: readback_ring_slots_from_raw(raw_slots),
        }
    }

    /// Return the ring whose staging slots can hold `byte_len`.
    ///
    /// # Errors
    ///
    /// Returns a backend error if the requested byte length overflows wgpu copy
    /// alignment.
    pub fn ring_for(
        &self,
        device: &wgpu::Device,
        byte_len: u64,
    ) -> Result<Arc<ReadbackRing>, BackendError> {
        let capacity = Self::capacity_class_for(byte_len)?;
        self.ring_for_capacity(device, capacity)
    }

    /// Return a ring for an already-normalized capacity class.
    #[inline]
    pub(crate) fn ring_for_capacity(
        &self,
        device: &wgpu::Device,
        capacity: u64,
    ) -> Result<Arc<ReadbackRing>, BackendError> {
        Ok(match self.rings.entry(capacity) {
            Entry::Occupied(entry) => Arc::clone(entry.get()),
            Entry::Vacant(entry) => {
                let ring = Arc::new(ReadbackRing::new(device, self.slots_per_ring, capacity)?);
                entry.insert(Arc::clone(&ring));
                ring
            }
        })
    }

    /// Convert an arbitrary byte length to the ring capacity class used for
    /// ring sizing.
    #[inline]
    pub(crate) fn capacity_class(byte_len: u64) -> Result<u64, BackendError> {
        Self::capacity_class_for(byte_len)
    }

    /// Convert an arbitrary byte length to the ring capacity class used for
    /// ring sizing.
    #[inline]
    pub(crate) fn capacity_class_for(byte_len: u64) -> Result<u64, BackendError> {
        ring_capacity_class(byte_len)
    }

    /// Return an existing size-classed ring without taking exclusive access.
    ///
    /// # Errors
    ///
    /// Returns a backend error if the requested byte length overflows wgpu copy
    /// alignment.
    pub fn existing_ring_for(
        &self,
        byte_len: u64,
    ) -> Result<Option<Arc<ReadbackRing>>, BackendError> {
        let capacity = Self::capacity_class(byte_len)?;
        Ok(self.existing_ring_for_capacity(capacity))
    }

    /// Return an existing size-classed ring without taking exclusive access.
    #[inline]
    pub(crate) fn existing_ring_for_capacity(&self, capacity: u64) -> Option<Arc<ReadbackRing>> {
        self.rings
            .get(&capacity)
            .map(|ring| Arc::clone(ring.value()))
    }

    /// Number of slots configured for each runtime ring instance.
    #[must_use]
    pub fn slots_per_ring(&self) -> usize {
        self.slots_per_ring
    }
}

/// Async readback ring buffer with GPU-resident staging buffers.
pub struct ReadbackRing {
    slots: Vec<GpuSlot>,
    stats: Arc<RingStats>,
    next_idx: AtomicU64,
}

impl ReadbackRing {
    /// Construct a ring with N staging buffers.
    #[must_use]
    pub fn new(device: &wgpu::Device, size: usize, buffer_size: u64) -> Result<Self, BackendError> {
        let size = size.clamp(MIN_RING_SIZE, MAX_RING_SIZE);
        let capacity = staging_capacity(buffer_size)?;
        let mut slots = Vec::new();
        reserve_backend_vec(&mut slots, size, "readback ring slot table")?;
        for i in 0..size {
            let buffer = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some(&format!("vyre readback ring slot {i}")),
                size: capacity,
                usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
                mapped_at_creation: false,
            });
            slots.push(GpuSlot {
                buffer,
                state: Arc::new(std::sync::atomic::AtomicU8::new(SLOT_FREE)),
                byte_len: AtomicU64::new(0),
                mapped_len: AtomicU64::new(0),
                capacity,
            });
        }
        Ok(Self {
            slots,
            stats: Arc::new(RingStats::default()),
            next_idx: AtomicU64::new(0),
        })
    }

    /// Record a readback copy into the next available ring slot.
    ///
    /// The caller must submit the encoder and then arm the returned ticket with
    /// [`Self::arm_ticket`]. This path lets the main dispatch encoder copy into
    /// preallocated ring slots instead of allocating a fresh staging buffer per
    /// output.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if the byte range cannot be represented, the
    /// ring slot would wrap before collection, or the requested readback exceeds
    /// slot capacity.
    pub fn record_copy(
        &self,
        device: &wgpu::Device,
        encoder: &mut wgpu::CommandEncoder,
        src_buffer: &wgpu::Buffer,
        src_offset: u64,
        byte_len: u64,
    ) -> Result<ReadbackTicket, BackendError> {
        let idx = self.next_slot_index()?;
        let slot = &self.slots[idx];
        let mapped_len = aligned_copy_len(byte_len)?;
        if mapped_len > slot.capacity {
            return Err(BackendError::new(format!(
                "readback request of {byte_len} bytes ({} bytes after wgpu copy alignment) exceeds ring slot capacity {} bytes. Fix: construct ReadbackRing with a buffer_size at least as large as the largest readback.",
                mapped_len, slot.capacity
            )));
        }

        if slot.state.load(Ordering::Acquire) == SLOT_PENDING {
            self.stats.record_stall();
            crate::runtime::device::poll_device_once(device)?;
        }
        if slot.state.load(Ordering::Acquire) != SLOT_FREE {
            return Err(BackendError::new(format!(
                "readback ring slot {idx} wrapped before collection. Fix: collect ready/error slots before submitting enough readbacks to reuse the same slot."
            )));
        }

        slot.byte_len.store(byte_len, Ordering::Release);
        slot.mapped_len.store(mapped_len, Ordering::Release);
        slot.state.store(SLOT_PENDING, Ordering::Release);
        if mapped_len != 0 {
            encoder.copy_buffer_to_buffer(src_buffer, src_offset, &slot.buffer, 0, mapped_len);
        } else {
            slot.state.store(SLOT_READY, Ordering::Release);
        }
        self.stats.record_dispatch();
        Ok(ReadbackTicket {
            idx,
            byte_len,
            mapped_len,
        })
    }

    /// Arm a submitted ticket by registering its `map_async` callback.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when `ticket` does not reference a live slot.
    pub fn arm_ticket(
        &self,
        ticket: &ReadbackTicket,
    ) -> Result<(Receiver<MapResult>, Arc<AtomicBool>), BackendError> {
        let Some(slot) = self.slots.get(ticket.idx) else {
            return Err(BackendError::new(format!(
                "readback ring ticket slot {} is out of bounds for {} slots. Fix: keep tickets paired with their originating ring.",
                ticket.idx,
                self.slots.len()
            )));
        };
        let (sender, receiver) = crossbeam_channel::bounded(1);
        let ready = Arc::new(AtomicBool::new(false));
        if ticket.mapped_len == 0 {
            if let Err(error) = sender.send(Ok(())) {
                tracing::error!(
                    ?error,
                    "readback ring zero-length callback result was lost because the receiver dropped"
                );
            }
            ready.store(true, Ordering::Release);
            return Ok((receiver, ready));
        }

        let state = Arc::clone(&slot.state);
        let ready_cb = Arc::clone(&ready);
        slot.buffer
            .slice(0..ticket.mapped_len)
            .map_async(wgpu::MapMode::Read, move |result| {
                match &result {
                    Ok(()) => state.store(SLOT_READY, Ordering::Release),
                    Err(error) => {
                        tracing::error!(
                            "readback ring map_async failed: {error:?}. Fix: inspect device health and readback buffer usage."
                        );
                        state.store(SLOT_ERROR, Ordering::Release);
                    }
                }
                if let Err(error) = sender.send(result) {
                    tracing::error!(
                        ?error,
                        "readback ring callback result was lost because the receiver dropped"
                    );
                }
                ready_cb.store(true, Ordering::Release);
            });
        Ok((receiver, ready))
    }

    /// Expose a ready ticket's mapped bytes to `visitor`, then free the slot.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the ticket is stale, the slot is not ready,
    /// or mapped length metadata is inconsistent.
    pub fn with_mapped_ticket<R>(
        &self,
        ticket: &ReadbackTicket,
        visitor: impl FnOnce(&[u8]) -> Result<R, BackendError>,
    ) -> Result<R, BackendError> {
        let Some(slot) = self.slots.get(ticket.idx) else {
            return Err(BackendError::new(format!(
                "readback ring ticket slot {} is out of bounds for {} slots. Fix: keep tickets paired with their originating ring.",
                ticket.idx,
                self.slots.len()
            )));
        };
        match slot.state.load(Ordering::Acquire) {
            SLOT_READY => {}
            SLOT_ERROR => {
                slot.byte_len.store(0, Ordering::Release);
                slot.mapped_len.store(0, Ordering::Release);
                slot.state.store(SLOT_FREE, Ordering::Release);
                return Err(BackendError::new(
                    "readback ring map_async failed. Fix: inspect GPU device health and ensure the slot buffer has MAP_READ usage.",
                ));
            }
            _ => {
                return Err(BackendError::new(
                    "readback ring ticket was collected before its map callback completed. Fix: poll the device or wait for the submitted GPU work before collection.",
                ));
            }
        }

        let len = usize::try_from(ticket.byte_len).map_err(|source| {
            BackendError::new(format!(
                "readback ring byte length {} cannot fit usize: {source}. Fix: split the readback before collecting it.",
                ticket.byte_len
            ))
        })?;
        if ticket.mapped_len == 0 {
            slot.byte_len.store(0, Ordering::Release);
            slot.mapped_len.store(0, Ordering::Release);
            slot.state.store(SLOT_FREE, Ordering::Release);
            return visitor(&[]);
        }
        let view = slot.buffer.slice(0..ticket.mapped_len).get_mapped_range();
        if len > view.len() {
            let mapped_len = view.len();
            drop(view);
            slot.buffer.unmap();
            slot.byte_len.store(0, Ordering::Release);
            slot.mapped_len.store(0, Ordering::Release);
            slot.state.store(SLOT_FREE, Ordering::Release);
            return Err(BackendError::new(format!(
                "readback ring mapped length {mapped_len} is shorter than requested length {len}. Fix: keep ticket and slot byte lengths synchronized."
            )));
        }
        let result = visitor(&view[..len]);
        drop(view);
        slot.buffer.unmap();
        slot.byte_len.store(0, Ordering::Release);
        slot.mapped_len.store(0, Ordering::Release);
        slot.state.store(SLOT_FREE, Ordering::Release);
        result
    }

    /// Submit a copy and mark the slot pending.
    ///
    /// # Errors
    /// Returns [\`BackendError\`] if encoder or queue submission fails.
    pub fn submit_readback(
        &self,
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        src_buffer: &wgpu::Buffer,
        byte_len: u64,
    ) -> Result<usize, BackendError> {
        let idx = self.next_slot_index()?;
        let slot = &self.slots[idx];
        let mapped_len = aligned_copy_len(byte_len)?;
        if mapped_len > slot.capacity {
            return Err(BackendError::new(format!(
                "readback request of {byte_len} bytes ({} bytes after wgpu copy alignment) exceeds ring slot capacity {} bytes. Fix: construct ReadbackRing with a buffer_size at least as large as the largest readback.",
                mapped_len, slot.capacity
            )));
        }

        if slot.state.load(Ordering::Acquire) == SLOT_PENDING {
            self.stats.record_stall();
            crate::runtime::device::poll_device_once(device)?;
        }
        if slot.state.load(Ordering::Acquire) != SLOT_FREE {
            return Err(BackendError::new(format!(
                "readback ring slot {idx} wrapped before collection. Fix: collect ready/error slots before submitting enough readbacks to reuse the same slot."
            )));
        }

        let state_clone = Arc::clone(&slot.state);
        slot.byte_len.store(byte_len, Ordering::Release);
        slot.mapped_len.store(mapped_len, Ordering::Release);
        state_clone.store(SLOT_PENDING, Ordering::Release);

        if mapped_len == 0 {
            state_clone.store(SLOT_READY, Ordering::Release);
            self.stats.record_dispatch();
            return Ok(idx);
        }

        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("vyre readback ring copy"),
        });
        encoder.copy_buffer_to_buffer(src_buffer, 0, &slot.buffer, 0, mapped_len);
        queue.submit(std::iter::once(encoder.finish()));

        slot.buffer
            .slice(0..mapped_len)
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
        let mut data = Vec::new();
        if self.collect_slot_into(device, idx, &mut data)?.is_some() {
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    /// Try to collect data from a specific slot into a caller-owned buffer.
    ///
    /// Reusing `out` avoids an allocation on every ready readback. The buffer is
    /// cleared before bytes are appended.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when `idx` is out of bounds or `map_async`
    /// failed for the slot.
    pub fn collect_slot_into(
        &self,
        device: &wgpu::Device,
        idx: usize,
        out: &mut Vec<u8>,
    ) -> Result<Option<usize>, BackendError> {
        let Some(slot) = self.slots.get(idx) else {
            return Err(BackendError::new(format!(
                "readback ring slot index {idx} is out of bounds for {} slots. Fix: collect only indices returned by submit_readback.",
                self.slots.len()
            )));
        };
        match slot.state.load(Ordering::Acquire) {
            SLOT_READY => {
                let len = self.copy_ready_slot_into(idx, out)?;
                Ok(Some(len))
            }
            SLOT_ERROR => {
                slot.byte_len.store(0, Ordering::Release);
                slot.mapped_len.store(0, Ordering::Release);
                slot.state.store(SLOT_FREE, Ordering::Release);
                Err(BackendError::new(
                    "readback ring map_async failed. Fix: inspect GPU device health and ensure the slot buffer has MAP_READ usage.",
                ))
            }
            _ => {
                crate::runtime::device::poll_device_once(device)?;
                Ok(None)
            }
        }
    }

    fn copy_ready_slot_into(&self, idx: usize, out: &mut Vec<u8>) -> Result<usize, BackendError> {
        let slot = &self.slots[idx];
        let byte_len = slot.byte_len.load(Ordering::Acquire);
        let mapped_len = slot.mapped_len.load(Ordering::Acquire);
        let len = usize::try_from(byte_len).map_err(|source| {
            BackendError::new(format!(
                "readback ring byte length {byte_len} cannot fit usize: {source}. Fix: split the readback before collecting it."
            ))
        })?;
        if mapped_len != 0 {
            let view = slot.buffer.slice(0..mapped_len).get_mapped_range();
            let bytes = &view[..len];
            if out.len() == len {
                out.copy_from_slice(bytes);
            } else {
                out.clear();
                if len > out.capacity() {
                    let additional = len - out.capacity();
                    out.try_reserve_exact(additional).map_err(|source| {
                        BackendError::new(format!(
                            "readback ring collection could not reserve {len} output bytes exactly: {source}. Fix: lower max_output_bytes or collect readback in smaller shards."
                        ))
                    })?;
                }
                out.extend_from_slice(bytes);
            }
            drop(view);
            slot.buffer.unmap();
        } else {
            out.clear();
        }
        slot.byte_len.store(0, Ordering::Release);
        slot.mapped_len.store(0, Ordering::Release);
        slot.state.store(SLOT_FREE, Ordering::Release);
        Ok(len)
    }

    #[inline]
    fn next_slot_index(&self) -> Result<usize, BackendError> {
        let slot_len = u64::try_from(self.slots.len()).map_err(|source| {
            BackendError::new(format!(
                "readback ring slot count {} cannot fit u64: {source}. Fix: reduce readback ring slot count.",
                self.slots.len()
            ))
        })?;
        if slot_len == 0 {
            return Err(BackendError::new(
                "readback ring has zero slots. Fix: construct rings with at least two slots.",
            ));
        }
        let next = rebasing_atomic_next_u64(
            &self.next_idx,
            0,
            Ordering::Relaxed,
            Ordering::Relaxed,
            Ordering::Relaxed,
            |_, _| {
                tracing::error!(
                    "readback ring slot counter reached u64::MAX and was rebased to zero. Fix: shard readback rings or scrape counters before wrap."
                );
            },
        );
        usize::try_from(next % slot_len).map_err(|source| {
            BackendError::new(format!(
                "readback ring slot index cannot fit usize: {source}. Fix: reduce readback ring slot count."
            ))
        })
    }
}

#[inline]

fn staging_capacity(byte_len: u64) -> Result<u64, BackendError> {
    aligned_copy_len(byte_len).map_err(|error| {
        tracing::warn!(
            "readback ring staging capacity overflowed for {byte_len} bytes: {error}. Fix: shard the readback buffer before constructing the ring."
        );
        error
    }).map(|len| len.max(4))
}

#[inline]
fn ring_capacity_class(byte_len: u64) -> Result<u64, BackendError> {
    let aligned = aligned_copy_len(byte_len)?.max(4);
    aligned
        .checked_add(RING_CAPACITY_GRANULARITY - 1)
        .map(|len| len & !(RING_CAPACITY_GRANULARITY - 1))
        .ok_or_else(|| {
            BackendError::new(
                "readback ring capacity class overflows u64. Fix: split the readback before submitting it to the ring.",
            )
        })
}

#[inline]
fn aligned_copy_len(byte_len: u64) -> Result<u64, BackendError> {
    crate::numeric::align_up_u64(byte_len, 0, "readback byte length")
}

fn readback_ring_slots_from_env() -> usize {
    let raw = std::env::var("VYRE_WGPU_READBACK_RING_SLOTS").ok();
    readback_ring_slots_from_raw(raw.as_deref())
}

fn readback_ring_slots_from_raw(raw: Option<&str>) -> usize {
    let Some(raw) = raw else {
        return DEFAULT_RING_SLOTS;
    };
    let slots = match raw.parse::<usize>() {
        Ok(0) => {
            tracing::warn!(
                "VYRE_WGPU_READBACK_RING_SLOTS=0 is invalid for GPU readback rings; defaulting to {MIN_RING_SIZE}. Fix: set it to a positive integer between {MIN_RING_SIZE} and {MAX_RING_SIZE}, or unset it."
            );
            MIN_RING_SIZE
        }
        Ok(value) if value > MAX_RING_SIZE => {
            tracing::warn!(
                "VYRE_WGPU_READBACK_RING_SLOTS={value} exceeds the safe cap of {MAX_RING_SIZE}; clamping.
                Fix: set it to an integer between {MIN_RING_SIZE} and {MAX_RING_SIZE}, or unset it."
            );
            MAX_RING_SIZE
        }
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(
                "VYRE_WGPU_READBACK_RING_SLOTS={raw:?} is invalid ({error:?}); defaulting to {DEFAULT_RING_SLOTS}. Fix: set it to a positive integer between {MIN_RING_SIZE} and {MAX_RING_SIZE}, or unset it."
            );
            DEFAULT_RING_SLOTS
        }
    };
    slots.clamp(MIN_RING_SIZE, MAX_RING_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_class_classifies_by_alignment_and_granularity() {
        assert_eq!(
            ReadbackRingSet::capacity_class_for(16).unwrap(),
            4096,
            "16-byte requests must promote to 4096-byte slot class"
        );
        assert_eq!(
            ReadbackRingSet::capacity_class_for(1).unwrap(),
            4096,
            "1-byte requests must promote to minimum aligned 4096-byte class"
        );
        assert_eq!(
            ReadbackRingSet::capacity_class_for(4097).unwrap(),
            8192,
            "4KB boundary crossings must promote to the next class"
        );
    }

    #[test]
    fn existing_ring_for_and_capacity_variant_agree_on_lookup_key() {
        let ring_set = ReadbackRingSet::new();
        let from_raw = ring_set
            .existing_ring_for(16)
            .expect("Fix: lookup with raw byte length should not fail");
        let from_class = ring_set.existing_ring_for_capacity(4096);
        assert!(
            from_raw.is_none() && from_class.is_none(),
            "raw and capacity-based lookups should agree on an empty set"
        );
    }

    #[test]
    fn production_ring_construction_uses_fallible_slot_reservation() {
        let production = include_str!("readback_ring.rs")
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .expect("Fix: readback ring production section should precede tests");

        assert!(
            !production.contains("Vec::with_capacity(size)"),
            "Fix: readback ring construction must not allocate slot tables infallibly."
        );
        assert!(
            production.contains("reserve_backend_vec(&mut slots, size, \"readback ring slot table\")?"),
            "Fix: readback ring construction should reserve slot tables through the shared WGPU staging helper."
        );
    }
}

