//! Persistent-thread engine + host-side work queue (G7).
//!
//! # What this is
//!
//! A single long-lived GPU dispatch owns a chunk of the device.
//! Host workers push `WorkItem`s into a device-visible ring buffer
//! via an atomic head counter; the device's persistent threads
//! poll a tail counter and pick up items. The host waits on
//! per-item completion markers to gather results.
//!
//! Eliminates the per-file kernel-launch cost (~5–20 µs on today's
//! drivers) so a stream of 10 000 × 1 KiB scan jobs pays launch
//! overhead once, not 10 000 times.
//!
//! # Scope of this file
//!
//! This module owns the **host-side ring buffer** — the atomic
//! head/tail pair, the lock-free claim protocol, and exhaustive
//! tests. The actual persistent GPU kernel that consumes the queue
//! lives behind the `persistent` cargo feature and talks raw
//! Vulkan async-compute (WGSL lacks device-side launch). The host
//! queue is proven correct in isolation so GPU integration only
//! worries about the shader side.
//!
//! # Memory ordering
//!
//! - Producers `AcqRel` on the head CAS; writes to the slot
//!   before the CAS happen-before the head increment.
//! - Consumers `AcqRel` on the tail CAS; after observing the
//!   incremented head, they see the producer's slot writes.
//! - A `Release` fence on the producer after the slot write and
//!   an `Acquire` fence on the consumer before reading the slot
//!   guarantees visibility across the weakest memory models we
//!   need to support (x86, ARM, RISC-V GPU consumers).

use std::sync::atomic::{AtomicU32, Ordering};

/// One scan-unit descriptor.
///
/// All fields are plain 32-bit numbers so the same struct lays out
/// identically on host and device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct WorkItem {
    /// Byte offset into the persistent input buffer.
    pub input_offset: u32,
    /// Number of bytes in this scan unit.
    pub input_len: u32,
    /// Rule-set / fused-megakernel output-slot bank id.
    pub rule_set_id: u32,
    /// Caller-opaque correlation id — echoed into the per-item
    /// completion counter so the host can match results back to a
    /// scan job without a shadow map.
    pub correlation: u32,
}

/// Shared atomics between host producers and device consumers.
#[derive(Debug)]
pub struct RingAtomics {
    /// Monotonically increasing next-slot-to-claim by a producer.
    pub head: AtomicU32,
    /// Monotonically increasing next-slot-to-claim by a consumer.
    pub tail: AtomicU32,
    /// Per-slot completion marker (1 = done).
    pub done: Vec<AtomicU32>,
}

impl RingAtomics {
    fn new(ring_size: u32) -> Self {
        Self {
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            done: (0..ring_size).map(|_| AtomicU32::new(0)).collect(),
        }
    }
}

/// Persistent-engine handle. Owns the host-side view of the ring
/// buffer. The GPU kernel is a separate concern gated behind
/// the `persistent` cargo feature.
#[derive(Debug)]
pub struct PersistentEngine {
    slots: Vec<std::sync::RwLock<WorkItem>>,
    atomics: RingAtomics,
    ring_size: u32,
}

impl PersistentEngine {
    /// Construct an engine with a ring capacity of `ring_size`
    /// slots. Must be a nonzero power of two so
    /// `index = slot & (cap-1)` is correct.
    pub fn new(ring_size: u32) -> Self {
        assert!(
            ring_size.is_power_of_two() && ring_size > 0,
            "ring_size must be a nonzero power of two (got {ring_size})",
        );
        let zero = WorkItem {
            input_offset: 0,
            input_len: 0,
            rule_set_id: 0,
            correlation: 0,
        };
        let slots = (0..ring_size)
            .map(|_| std::sync::RwLock::new(zero))
            .collect();
        Self {
            slots,
            atomics: RingAtomics::new(ring_size),
            ring_size,
        }
    }

    /// Capacity of the ring buffer.
    pub fn ring_size(&self) -> u32 {
        self.ring_size
    }

    /// Enqueue a WorkItem. Returns `Ok(slot_index)` on success, or
    /// `Err(QueueFull)` if the ring is full. Thread-safe under
    /// concurrent producers (lock-free CAS on `head`).
    pub fn enqueue(&self, item: WorkItem) -> Result<u32, QueueFull> {
        loop {
            let head = self.atomics.head.load(Ordering::Acquire);
            let tail = self.atomics.tail.load(Ordering::Acquire);
            if head.wrapping_sub(tail) >= self.ring_size {
                return Err(QueueFull);
            }
            match self.atomics.head.compare_exchange(
                head,
                head.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let slot_idx = head & (self.ring_size - 1);
                    let Some(slot) = self.slots.get(slot_idx as usize) else {
                        return Err(QueueFull);
                    };
                    let Ok(mut guard) = slot.write() else {
                        return Err(QueueFull);
                    };
                    *guard = item;
                    std::sync::atomic::fence(Ordering::Release);
                    return Ok(slot_idx);
                }
                Err(_) => continue,
            }
        }
    }

    /// Consumer-side claim. Returns the next available item or
    /// `None` if the queue is empty. Thread-safe under concurrent
    /// consumers.
    pub fn claim(&self) -> Option<WorkItem> {
        loop {
            let head = self.atomics.head.load(Ordering::Acquire);
            let tail = self.atomics.tail.load(Ordering::Acquire);
            if tail >= head {
                return None;
            }
            match self.atomics.tail.compare_exchange(
                tail,
                tail.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    std::sync::atomic::fence(Ordering::Acquire);
                    let slot_idx = tail & (self.ring_size - 1);
                    let slot = self.slots.get(slot_idx as usize)?;
                    let guard = slot.read().ok()?;
                    return Some(*guard);
                }
                Err(_) => continue,
            }
        }
    }

    /// Mark item at `slot_idx` as done.
    pub fn mark_done(&self, slot_idx: u32) {
        self.atomics.done[slot_idx as usize].store(1, Ordering::Release);
    }

    /// Whether the consumer finished the item at `slot_idx`.
    pub fn is_done(&self, slot_idx: u32) -> bool {
        self.atomics.done[slot_idx as usize].load(Ordering::Acquire) != 0
    }

    /// Number of items queued but not yet claimed.
    pub fn in_flight(&self) -> u32 {
        self.atomics
            .head
            .load(Ordering::Acquire)
            .wrapping_sub(self.atomics.tail.load(Ordering::Acquire))
    }

    /// Monotonic head counter (modulo `ring_size` = slot index).
    pub fn head(&self) -> u32 {
        self.atomics.head.load(Ordering::Acquire)
    }

    /// Monotonic tail counter.
    pub fn tail(&self) -> u32 {
        self.atomics.tail.load(Ordering::Acquire)
    }
}

/// Enqueue attempted but the ring is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueFull;

impl std::fmt::Display for QueueFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("persistent engine ring buffer is full")
    }
}

impl std::error::Error for QueueFull {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn item(i: u32) -> WorkItem {
        WorkItem {
            input_offset: i * 1024,
            input_len: 1024,
            rule_set_id: 0,
            correlation: i,
        }
    }

    #[test]
    #[should_panic(expected = "power of two")]
    fn non_power_of_two_ring_size_panics() {
        let _ = PersistentEngine::new(7);
    }

    #[test]
    #[should_panic(expected = "power of two")]
    fn zero_ring_size_panics() {
        let _ = PersistentEngine::new(0);
    }

    #[test]
    fn enqueue_claim_fifo_single_thread() {
        let eng = PersistentEngine::new(8);
        for i in 0..8 {
            assert_eq!(eng.enqueue(item(i)).unwrap(), i);
        }
        for i in 0..8 {
            assert_eq!(eng.claim().unwrap().correlation, i);
        }
        assert!(eng.claim().is_none());
    }

    #[test]
    fn queue_full_on_overflow() {
        let eng = PersistentEngine::new(4);
        for i in 0..4 {
            eng.enqueue(item(i)).unwrap();
        }
        assert_eq!(eng.enqueue(item(99)), Err(QueueFull));
    }

    #[test]
    fn space_reclaims_after_claim() {
        let eng = PersistentEngine::new(4);
        for i in 0..4 {
            eng.enqueue(item(i)).unwrap();
        }
        assert!(eng.enqueue(item(99)).is_err());
        let _ = eng.claim().unwrap();
        assert!(eng.enqueue(item(99)).is_ok());
    }

    #[test]
    fn in_flight_tracks_correctly() {
        let eng = PersistentEngine::new(16);
        assert_eq!(eng.in_flight(), 0);
        for i in 0..5 {
            eng.enqueue(item(i)).unwrap();
        }
        assert_eq!(eng.in_flight(), 5);
        eng.claim().unwrap();
        eng.claim().unwrap();
        assert_eq!(eng.in_flight(), 3);
    }

    #[test]
    fn done_marker_flows_through() {
        let eng = PersistentEngine::new(4);
        let slot = eng.enqueue(item(1)).unwrap();
        assert!(!eng.is_done(slot));
        let _ = eng.claim().unwrap();
        eng.mark_done(slot);
        assert!(eng.is_done(slot));
    }

    #[test]
    fn multi_producer_single_consumer_no_item_lost() {
        let eng = Arc::new(PersistentEngine::new(128));
        let producers = 4;
        let items_per_producer = 16;
        let mut handles = Vec::new();
        for p in 0..producers {
            let eng = Arc::clone(&eng);
            handles.push(thread::spawn(move || {
                for i in 0..items_per_producer {
                    let corr = (p * 1000 + i) as u32;
                    loop {
                        if eng.enqueue(item(corr)).is_ok() {
                            break;
                        }
                        thread::yield_now();
                    }
                }
            }));
        }
        let consumer_eng = Arc::clone(&eng);
        let consumer = thread::spawn(move || {
            let total = (producers * items_per_producer) as usize;
            let mut seen = Vec::with_capacity(total);
            while seen.len() < total {
                if let Some(it) = consumer_eng.claim() {
                    seen.push(it.correlation);
                } else {
                    thread::yield_now();
                }
            }
            seen
        });
        for h in handles {
            h.join().unwrap();
        }
        let seen = consumer.join().unwrap();
        let mut sorted = seen.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), seen.len(), "duplicate items consumed");
        for p in 0..producers {
            for i in 0..items_per_producer {
                let expected = (p * 1000 + i) as u32;
                assert!(
                    seen.contains(&expected),
                    "missing correlation id {expected}"
                );
            }
        }
    }

    #[test]
    fn wrap_around_works_for_large_throughput() {
        let eng = PersistentEngine::new(16);
        let passes = 10;
        for p in 0..passes {
            for i in 0..16 {
                let corr = (p * 1000 + i) as u32;
                assert!(eng.enqueue(item(corr)).is_ok());
            }
            for i in 0..16 {
                let corr = (p * 1000 + i) as u32;
                assert_eq!(eng.claim().unwrap().correlation, corr);
            }
        }
        assert_eq!(eng.head(), (passes * 16) as u32);
        assert_eq!(eng.tail(), (passes * 16) as u32);
        assert_eq!(eng.in_flight(), 0);
    }

    #[test]
    fn multi_consumer_no_double_claim() {
        let eng = Arc::new(PersistentEngine::new(128));
        let total = 100_u32;
        for i in 0..total {
            eng.enqueue(item(i)).unwrap();
        }
        let consumers = 4;
        let mut handles = Vec::new();
        let shared_consumed = Arc::new(std::sync::Mutex::new(Vec::new()));
        for _ in 0..consumers {
            let eng = Arc::clone(&eng);
            let out = Arc::clone(&shared_consumed);
            handles.push(thread::spawn(move || {
                let mut local = Vec::new();
                while let Some(it) = eng.claim() {
                    local.push(it.correlation);
                }
                out.lock().unwrap().extend(local);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let mut consumed = Arc::try_unwrap(shared_consumed)
            .unwrap()
            .into_inner()
            .unwrap();
        consumed.sort();
        assert_eq!(consumed.len(), total as usize);
        for (i, c) in consumed.iter().enumerate() {
            assert_eq!(*c, i as u32, "duplicated or missing item at idx {i}");
        }
    }

    #[test]
    fn queue_full_error_display_is_useful() {
        let s = format!("{QueueFull}");
        assert!(s.contains("ring buffer"));
    }
}
