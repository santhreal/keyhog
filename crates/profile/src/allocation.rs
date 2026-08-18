//! Allocation counting and per-stage ownership behind the
//! `allocation-tracking` feature, following the `process-metrics` and
//! `hardware-counters` capability pattern.
//!
//! [`TrackingAllocator`] wraps the system allocator. Binaries install it with
//! `#[global_allocator]`; when the feature is disabled it compiles to a
//! transparent pass-through with no counters. When installed, every allocation
//! carries a 16-byte header recording the profiling stage active at allocation
//! time, so per-stage live bytes stay exact even when memory is freed from a
//! different stage or thread. All counters are process-wide atomics; a session
//! diffs snapshots taken at its boundaries. Nothing allocates on the recording
//! path.

use crate::collector::{CollectorAvailability, CollectorCapability, CollectorId};
use std::alloc::{GlobalAlloc, Layout, System};

/// Stage attribution slots: one per [`crate::Stage`] plus one root slot for
/// allocations made outside any recorded span.
pub const STAGE_SLOTS: usize = crate::runtime::STAGE_COUNT + 1;
/// Slot index for allocations made outside any recorded span.
pub const ROOT_SLOT: usize = crate::runtime::STAGE_COUNT;

#[cfg(feature = "allocation-tracking")]
mod tracked {
    use super::*;
    use std::cell::{Cell, UnsafeCell};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    const MAX_STAGE_DEPTH: usize = 64;
    const HEADER_BYTES: usize = 16;
    const HEADER_MAGIC: u8 = 0xA5;

    pub(super) static INSTALLED: AtomicBool = AtomicBool::new(false);
    /// Process-wide count of SystemSessions currently sampling allocation totals.
    static ACTIVE_ALLOC_SESSIONS: AtomicUsize = AtomicUsize::new(0);
    /// Sticky while any overlapping allocation sessions share the global counters.
    static ALLOC_SESSION_OVERLAP: AtomicBool = AtomicBool::new(false);
    static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
    static DEALLOCATIONS: AtomicU64 = AtomicU64::new(0);
    static ALLOCATION_BYTES: AtomicU64 = AtomicU64::new(0);
    static DEALLOCATION_BYTES: AtomicU64 = AtomicU64::new(0);
    static LIVE_BYTES: AtomicU64 = AtomicU64::new(0);
    static PEAK_LIVE_BYTES: AtomicU64 = AtomicU64::new(0);
    static SLOT_ALLOCATIONS: [AtomicU64; STAGE_SLOTS] = [const { AtomicU64::new(0) }; STAGE_SLOTS];
    static SLOT_ALLOCATION_BYTES: [AtomicU64; STAGE_SLOTS] =
        [const { AtomicU64::new(0) }; STAGE_SLOTS];
    static SLOT_DEALLOCATION_BYTES: [AtomicU64; STAGE_SLOTS] =
        [const { AtomicU64::new(0) }; STAGE_SLOTS];
    static SLOT_LIVE_BYTES: [AtomicU64; STAGE_SLOTS] = [const { AtomicU64::new(0) }; STAGE_SLOTS];
    static SLOT_PEAK_LIVE_BYTES: [AtomicU64; STAGE_SLOTS] =
        [const { AtomicU64::new(0) }; STAGE_SLOTS];

    thread_local! {
        static STAGE_STACK_DEPTH: Cell<u16> = const { Cell::new(0) };
        static STAGE_STACK: UnsafeCell<[u8; MAX_STAGE_DEPTH]> =
            const { UnsafeCell::new([0; MAX_STAGE_DEPTH]) };
    }

    /// Push one stage onto this thread's allocation-attribution stack.
    pub(crate) fn stage_context_push(stage: crate::Stage) {
        STAGE_STACK_DEPTH.with(|depth| {
            let current = depth.get();
            if (current as usize) < MAX_STAGE_DEPTH {
                STAGE_STACK.with(|stack| {
                    // SAFETY: thread-local stack slot below the depth bound;
                    // only this thread reads or writes it.
                    unsafe { (*stack.get())[current as usize] = stage.index() as u8 };
                });
            }
            depth.set(current.saturating_add(1));
        });
    }

    /// Pop the stage this thread most recently pushed; saturates on mismatch.
    pub(crate) fn stage_context_pop() {
        STAGE_STACK_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }

    fn current_slot() -> usize {
        STAGE_STACK_DEPTH.with(|depth| {
            let current = depth.get();
            if current == 0 || current as usize > MAX_STAGE_DEPTH {
                return ROOT_SLOT;
            }
            STAGE_STACK.with(|stack| {
                // SAFETY: current - 1 is below the depth bound and was written
                // by this thread when the frame was pushed.
                usize::from(unsafe { (*stack.get())[current as usize - 1] })
            })
        })
    }

    #[inline]
    fn record_alloc(slot: usize, bytes: u64) {
        INSTALLED.store(true, Ordering::Relaxed);
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        ALLOCATION_BYTES.fetch_add(bytes, Ordering::Relaxed);
        let live = LIVE_BYTES.fetch_add(bytes, Ordering::Relaxed) + bytes;
        PEAK_LIVE_BYTES.fetch_max(live, Ordering::Relaxed);
        SLOT_ALLOCATIONS[slot].fetch_add(1, Ordering::Relaxed);
        SLOT_ALLOCATION_BYTES[slot].fetch_add(bytes, Ordering::Relaxed);
        let slot_live = SLOT_LIVE_BYTES[slot].fetch_add(bytes, Ordering::Relaxed) + bytes;
        SLOT_PEAK_LIVE_BYTES[slot].fetch_max(slot_live, Ordering::Relaxed);
    }

    #[inline]
    fn record_dealloc(slot: usize, bytes: u64) {
        if slot >= STAGE_SLOTS {
            // Fail closed: a corrupt header must not index SLOT_* or wrap live
            // counters. Callers that already validated the header never hit this.
            return;
        }
        DEALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        DEALLOCATION_BYTES.fetch_add(bytes, Ordering::Relaxed);
        saturating_fetch_sub(&LIVE_BYTES, bytes);
        SLOT_DEALLOCATION_BYTES[slot].fetch_add(bytes, Ordering::Relaxed);
        saturating_fetch_sub(&SLOT_LIVE_BYTES[slot], bytes);
    }

    #[inline]
    fn saturating_fetch_sub(cell: &AtomicU64, bytes: u64) {
        let mut current = cell.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_sub(bytes);
            match cell.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    pub(super) fn snapshot_totals() -> (u64, u64, u64, u64, u64, u64) {
        (
            ALLOCATIONS.load(Ordering::Relaxed),
            DEALLOCATIONS.load(Ordering::Relaxed),
            ALLOCATION_BYTES.load(Ordering::Relaxed),
            DEALLOCATION_BYTES.load(Ordering::Relaxed),
            LIVE_BYTES.load(Ordering::Relaxed),
            PEAK_LIVE_BYTES.load(Ordering::Relaxed),
        )
    }

    pub(super) fn snapshot_slot(slot: usize) -> super::AllocationSlotV2 {
        let allocated = SLOT_ALLOCATION_BYTES[slot].load(Ordering::Relaxed);
        let deallocated = SLOT_DEALLOCATION_BYTES[slot].load(Ordering::Relaxed);
        super::AllocationSlotV2 {
            allocations: SLOT_ALLOCATIONS[slot].load(Ordering::Relaxed),
            allocated_bytes: allocated,
            live_bytes: allocated.saturating_sub(deallocated),
            peak_live_bytes: SLOT_PEAK_LIVE_BYTES[slot].load(Ordering::Relaxed),
        }
    }

    pub(super) fn reset_peaks() {
        PEAK_LIVE_BYTES.store(LIVE_BYTES.load(Ordering::Relaxed), Ordering::Relaxed);
        for slot in 0..STAGE_SLOTS {
            SLOT_PEAK_LIVE_BYTES[slot].store(
                SLOT_LIVE_BYTES[slot].load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
        }
    }

    /// Enter a session window over the process-global allocation counters.
    ///
    /// Only the sole active session may reset peaks. A second concurrent
    /// session marks the process contaminated so every overlapping window
    /// fail-closes instead of publishing misattributed peaks/deltas.
    pub(super) fn enter_session() -> (bool, bool) {
        let prev = ACTIVE_ALLOC_SESSIONS.fetch_add(1, Ordering::AcqRel);
        if prev == 0 {
            ALLOC_SESSION_OVERLAP.store(false, Ordering::Release);
            reset_peaks();
            (true, false)
        } else {
            ALLOC_SESSION_OVERLAP.store(true, Ordering::Release);
            (true, true)
        }
    }

    pub(super) fn leave_session() {
        ACTIVE_ALLOC_SESSIONS.fetch_sub(1, Ordering::AcqRel);
    }

    pub(super) fn session_evidence_reliable(joined_overlapped: bool) -> bool {
        if joined_overlapped {
            return false;
        }
        if ALLOC_SESSION_OVERLAP.load(Ordering::Acquire) {
            return false;
        }
        ACTIVE_ALLOC_SESSIONS.load(Ordering::Acquire) == 1
    }

    #[repr(C)]
    struct AllocationHeader {
        stage: u8,
        magic: u8,
        reserved: [u8; 6],
        bytes: u64,
    }

    const _: () = assert!(std::mem::size_of::<AllocationHeader>() == HEADER_BYTES);

    /// Tracked allocation: header records the stage slot and requested bytes.
    // SAFETY: Caller must ensure layout meets GlobalAlloc invariants.
    pub(super) unsafe fn tracked_alloc(layout: Layout) -> *mut u8 {
        let offset = layout.align().max(HEADER_BYTES);
        let Some(total) = layout.size().checked_add(offset) else {
            return std::ptr::null_mut();
        };
        let Ok(real) = Layout::from_size_align(total, offset) else {
            return std::ptr::null_mut();
        };
        // SAFETY: real is a valid layout; the caller honors GlobalAlloc rules.
        let base = unsafe { System.alloc(real) };
        if base.is_null() {
            return base;
        }
        let slot = current_slot();
        let header = AllocationHeader {
            stage: slot as u8,
            magic: HEADER_MAGIC,
            reserved: [0; 6],
            bytes: layout.size() as u64,
        };
        // SAFETY: base is 16-aligned and owns at least HEADER_BYTES before the
        // user region at base + offset.
        unsafe { base.cast::<AllocationHeader>().write(header) };
        record_alloc(slot, layout.size() as u64);
        // SAFETY: offset lies inside the allocated block.
        unsafe { base.add(offset) }
    }

    /// Tracked deallocation: ownership returns to the allocating stage slot.
    ///
    /// Release builds previously trusted `AllocationHeader` with only
    /// `debug_assert`s. A corrupt `stage` indexed `SLOT_*` out of bounds
    /// (panic in the global allocator); a corrupt `bytes` fed
    /// `from_size_align_unchecked` and wrapping `fetch_sub`. Validate the
    /// header; on failure, free with the caller layout and skip counters.
    // SAFETY: Caller must ensure ptr was allocated by tracked_alloc with matching layout.
    pub(super) unsafe fn tracked_dealloc(ptr: *mut u8, layout: Layout) {
        let offset = layout.align().max(HEADER_BYTES);
        // SAFETY: ptr came from tracked_alloc with the same layout, so the
        // header sits exactly offset bytes before it.
        let base = unsafe { ptr.sub(offset) };
        // SAFETY: base points at the header written by tracked_alloc (or at
        // whatever bytes sit there if the block was corrupted).
        let header = unsafe { base.cast::<AllocationHeader>().read() };
        let stage = usize::from(header.stage);
        let header_ok = header.magic == HEADER_MAGIC
            && header.bytes == layout.size() as u64
            && stage < STAGE_SLOTS;
        let user_bytes = if header_ok {
            record_dealloc(stage, header.bytes);
            header.bytes as usize
        } else {
            // Skip counter updates; free with the caller-provided layout size.
            layout.size()
        };
        let real = Layout::from_size_align(user_bytes.saturating_add(offset), offset)
            .unwrap_or_else(|_| {
                // offset is align.max(16) so power-of-two and nonzero; size was
                // accepted at alloc time. Fall back only if saturating wrap
                // produced an impossible pair.
                // SAFETY: offset is a non-zero power-of-two alignment.
                unsafe { Layout::from_size_align_unchecked(layout.size() + offset, offset) }
            });
        // SAFETY: base/real match the allocation that produced ptr when the
        // header is valid; on corruption we free using the caller layout that
        // GlobalAlloc requires the client to pass.
        unsafe { System.dealloc(base, real) };
    }
}

#[cfg(not(feature = "allocation-tracking"))]
mod untracked {
    pub(super) fn snapshot_totals() -> (u64, u64, u64, u64, u64, u64) {
        (0, 0, 0, 0, 0, 0)
    }

    pub(super) fn snapshot_slot(_slot: usize) -> super::AllocationSlotV2 {
        super::AllocationSlotV2 {
            allocations: 0,
            allocated_bytes: 0,
            live_bytes: 0,
            peak_live_bytes: 0,
        }
    }

    pub(super) fn reset_peaks() {}
}

#[cfg(feature = "allocation-tracking")]
use tracked as backend;
#[cfg(not(feature = "allocation-tracking"))]
use untracked as backend;

#[cfg(feature = "allocation-tracking")]
pub(crate) use backend::{stage_context_pop, stage_context_push};

/// Push one stage onto this thread's attribution stack; no-op without the
/// `allocation-tracking` feature. Called by span guards only.
#[cfg(not(feature = "allocation-tracking"))]
#[inline(always)]
pub(crate) fn stage_context_push(_stage: crate::Stage) {}

/// Pop one stage from this thread's attribution stack; no-op without the
/// `allocation-tracking` feature. Called by span guards only.
#[cfg(not(feature = "allocation-tracking"))]
#[inline(always)]
pub(crate) fn stage_context_pop() {}

/// Global allocator that counts allocations, bytes, and live memory with
/// per-stage ownership. Install with `#[global_allocator]`. Without the
/// `allocation-tracking` feature every method inlines to the system allocator.
pub struct TrackingAllocator;

impl TrackingAllocator {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for TrackingAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: every method forwards a valid layout to the system allocator; the
// tracked variant keeps the GlobalAlloc contract for the returned pointers.
unsafe impl GlobalAlloc for TrackingAllocator {
    #[cfg(feature = "allocation-tracking")]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded from the caller.
        unsafe { tracked::tracked_alloc(layout) }
    }

    #[cfg(feature = "allocation-tracking")]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded from the caller with the matching layout.
        unsafe { tracked::tracked_dealloc(ptr, layout) }
    }

    #[cfg(not(feature = "allocation-tracking"))]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded from the caller.
        unsafe { System.alloc(layout) }
    }

    #[cfg(not(feature = "allocation-tracking"))]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded from the caller with the matching layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// Whether any tracked allocation has run through a [`TrackingAllocator`].
pub fn allocation_tracking_installed() -> bool {
    #[cfg(feature = "allocation-tracking")]
    {
        tracked::INSTALLED.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(not(feature = "allocation-tracking"))]
    {
        false
    }
}

/// Per-slot allocation counters at one instant.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocationSlotV2 {
    pub allocations: u64,
    pub allocated_bytes: u64,
    pub live_bytes: u64,
    pub peak_live_bytes: u64,
}

/// Process-wide allocation counters at one instant, split by owning stage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationSnapshotV2 {
    pub allocations: u64,
    pub deallocations: u64,
    pub allocated_bytes: u64,
    pub deallocated_bytes: u64,
    pub live_bytes: u64,
    pub peak_live_bytes: u64,
    /// One slot per [`crate::Stage`] in wire order plus the root slot.
    pub slots: [AllocationSlotV2; STAGE_SLOTS],
}

impl AllocationSnapshotV2 {
    /// Counters owned by one stage, or the root slot for unattributed work.
    pub fn slot(&self, stage: crate::Stage) -> &AllocationSlotV2 {
        &self.slots[stage.index()]
    }

    /// Counters for allocations made outside any recorded span.
    pub fn root(&self) -> &AllocationSlotV2 {
        &self.slots[ROOT_SLOT]
    }

    /// Live bytes delta between two snapshots.
    pub fn live_delta_since(&self, start: &Self) -> u64 {
        self.live_bytes.saturating_sub(start.live_bytes)
    }
}

/// Snapshot the process-wide allocation counters; all zeros when the
/// `allocation-tracking` feature is disabled.
pub fn allocation_snapshot() -> AllocationSnapshotV2 {
    let (allocations, deallocations, allocated_bytes, deallocated_bytes, live_bytes, peak) =
        backend::snapshot_totals();
    AllocationSnapshotV2 {
        allocations,
        deallocations,
        allocated_bytes,
        deallocated_bytes,
        live_bytes,
        peak_live_bytes: peak,
        slots: std::array::from_fn(backend::snapshot_slot),
    }
}

/// Restart peak-live tracking from the current live levels.
///
/// A sole session calls this at start so its reported peak covers exactly its
/// own window. The tracker is process-wide: overlapping sessions must not reset
/// each other's peaks — `SystemSession` enforces that fail-closed.
pub fn reset_allocation_peaks() {
    backend::reset_peaks();
}

/// RAII participation in the process-global allocation session window.
///
/// Dropping the token leaves the active-session count. Evidence is reliable
/// only while this token is the sole uncontaminated participant.
pub(crate) struct AllocationSessionToken {
    active: bool,
    overlapped: bool,
}

impl AllocationSessionToken {
    pub(crate) const fn inactive() -> Self {
        Self {
            active: false,
            overlapped: false,
        }
    }

    pub(crate) fn evidence_is_reliable(&self) -> bool {
        if !self.active {
            return true;
        }
        #[cfg(feature = "allocation-tracking")]
        {
            backend::session_evidence_reliable(self.overlapped)
        }
        #[cfg(not(feature = "allocation-tracking"))]
        {
            true
        }
    }
}

impl Drop for AllocationSessionToken {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        #[cfg(feature = "allocation-tracking")]
        {
            backend::leave_session();
        }
    }
}

/// Snapshot-then-enter helper used by [`crate::system::SystemSession`].
///
/// Peaks reset only when this session is the sole active participant.
pub(crate) fn enter_allocation_session() -> AllocationSessionToken {
    #[cfg(feature = "allocation-tracking")]
    {
        let (active, overlapped) = backend::enter_session();
        AllocationSessionToken { active, overlapped }
    }
    #[cfg(not(feature = "allocation-tracking"))]
    {
        AllocationSessionToken::inactive()
    }
}

pub(crate) fn allocation_capability() -> CollectorCapability {
    #[cfg(not(feature = "allocation-tracking"))]
    {
        CollectorCapability::unavailable(
            CollectorId::AllocationTracking,
            CollectorAvailability::Disabled,
            "enable the keyhog-profile allocation-tracking feature",
        )
    }
    #[cfg(feature = "allocation-tracking")]
    {
        if allocation_tracking_installed() {
            CollectorCapability::available(CollectorId::AllocationTracking)
        } else {
            CollectorCapability::unavailable(
                CollectorId::AllocationTracking,
                CollectorAvailability::Unavailable,
                "install keyhog_profile::TrackingAllocator as the global allocator to count allocations",
            )
        }
    }
}
