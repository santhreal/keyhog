//! Power-of-two GPU buffer pool for persistent dispatch.

use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use crossbeam_queue::ArrayQueue;
use vyre_driver::{BackendError, DispatchConfig};

use super::handle::GpuBufferHandle;

#[derive(Debug, Default)]
#[repr(align(64))]
struct PaddedAtomicUsize(AtomicUsize);

impl PaddedAtomicUsize {
    fn new(value: usize) -> Self {
        Self(AtomicUsize::new(value))
    }

    fn load(&self, order: Ordering) -> usize {
        self.0.load(order)
    }

    fn fetch_add(&self, value: usize, order: Ordering) -> usize {
        self.0.fetch_add(value, order)
    }

    fn fetch_sub(&self, value: usize, order: Ordering) -> usize {
        self.0.fetch_sub(value, order)
    }
}

/// Snapshot of [`BufferPool`] counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BufferPoolStats {
    /// docs
    pub allocations: usize,
    /// docs
    pub hits: usize,
    /// docs
    pub releases: usize,
    /// docs
    pub evictions: usize,
    /// docs
    pub retained_bytes: usize,
}

#[derive(Debug)]
pub(crate) struct PoolStats {
    allocations: PaddedAtomicUsize,
    hits: PaddedAtomicUsize,
    releases: PaddedAtomicUsize,
    evictions: PaddedAtomicUsize,
    retained_bytes: PaddedAtomicUsize,
}

impl Default for PoolStats {
    fn default() -> Self {
        Self {
            allocations: PaddedAtomicUsize::new(0),
            hits: PaddedAtomicUsize::new(0),
            releases: PaddedAtomicUsize::new(0),
            evictions: PaddedAtomicUsize::new(0),
            retained_bytes: PaddedAtomicUsize::new(0),
        }
    }
}

#[derive(Clone)]
pub(crate) struct PoolReturn {
    inner: Weak<PoolInner>,
}

/// Reusable GPU buffer pool.
#[derive(Clone)]
pub struct BufferPool {
    inner: Arc<PoolInner>,
}

impl fmt::Debug for BufferPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BufferPool")
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

const NUM_SIZE_CLASSES: usize = 64;

/// Canonical usage masks used to key each size-class sub-bucket.
///
/// Reduces the full `wgpu::BufferUsages` bitfield to a small enum so
/// that alternating workloads (e.g. INPUT vs OUTPUT) no longer
/// collide in the same queue and fall through to fresh allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
enum UsageKind {
    Input = 0,
    Output = 1,
    Uniform = 2,
    Workgroup = 3,
    Other = 4,
}

const NUM_USAGE_KINDS: usize = 5;

fn canonical_usage_kind(usage: wgpu::BufferUsages) -> UsageKind {
    use wgpu::BufferUsages as U;
    if usage == U::STORAGE | U::COPY_DST {
        UsageKind::Input
    } else if usage == U::STORAGE | U::COPY_SRC | U::COPY_DST | U::INDIRECT {
        UsageKind::Output
    } else if usage == U::UNIFORM | U::COPY_DST {
        UsageKind::Uniform
    } else if usage == U::STORAGE | U::COPY_SRC | U::COPY_DST {
        UsageKind::Workgroup
    } else {
        UsageKind::Other
    }
}

/// Opt-in hot/cold tiered caching layered over the power-of-two pool.
///
/// Off by default. Consumers that batch many small dispatches (inference
/// servers, Karyx streaming scanners, Soleno batched probes) wire one
/// via [`BufferPool::with_tiering`] and tag hot allocations through the
/// returned handle. The tiering layer classifies each allocation and
/// demotes/evicts via `TieredCache`'s per-tier O(1) LRU.
///
/// Kept as `pub(crate) Option<Arc<...>>` so the absence of a tiering
/// policy costs exactly one `Option::is_none()` branch on the hot
/// acquire path.
pub(crate) type PoolTiering = std::sync::Mutex<crate::runtime::cache::TieredCache>;

struct PoolInner {
    device: wgpu::Device,
    queue: wgpu::Queue,
    free: [[ArrayQueue<FreeEntry>; NUM_USAGE_KINDS]; NUM_SIZE_CLASSES],
    non_empty_classes: AtomicU64,
    stats: PoolStats,
    max_retained_bytes: usize,
    /// Optional tiered cache. `None` = power-of-two pool only.
    tiering: Option<Arc<PoolTiering>>,
}

struct FreeEntry {
    buffer: Arc<wgpu::Buffer>,
    allocation_len: u64,
    element_count: usize,
    usage: wgpu::BufferUsages,
}

impl BufferPool {
    #[must_use]
    /// docs
    pub fn new(device: wgpu::Device, queue: wgpu::Queue, config: &DispatchConfig) -> Self {
        let capacity = config.max_output_bytes.unwrap_or(1024);
        let max_retained_bytes = config.max_output_bytes.unwrap_or(1 << 30);
        let free = std::array::from_fn(|_| std::array::from_fn(|_| ArrayQueue::new(capacity)));
        Self {
            inner: Arc::new(PoolInner {
                device,
                queue,
                free,
                non_empty_classes: AtomicU64::new(0),
                stats: PoolStats::default(),
                max_retained_bytes,
                tiering: None,
            }),
        }
    }

    /// Opt-in hot/cold tiered caching on top of the power-of-two pool.
    ///
    /// Returns a new `BufferPool` that shares the underlying device
    /// and queue but wraps every acquire/release in a `TieredCache`
    /// governed by the supplied tiers + policy. Consumers that batch
    /// many small dispatches (inference servers, streaming scanners,
    /// batched probes) use this to keep hot allocations resident and
    /// demote/evict cold ones via per-tier O(1) LRU.
    ///
    /// The `tiers` vector is ordered coldest-first; `policy` controls
    /// promotion/eviction. Defaults at
    /// `TieredCache::new(vec![CacheTier::new("hot", 1 << 24),
    /// CacheTier::new("cold", 1 << 30)])` are a reasonable starting
    /// point for 16 MiB hot / 1 GiB cold.
    #[must_use]
    pub fn with_tiering(
        device: wgpu::Device,
        queue: wgpu::Queue,
        config: &DispatchConfig,
        tiers: Vec<crate::runtime::cache::CacheTier>,
    ) -> Self {
        let mut pool = Self::new(device, queue, config);
        let tiered = crate::runtime::cache::TieredCache::new(tiers);
        // Safe: inner has no other owners yet, make_mut returns
        // unique &mut.
        if let Some(inner) = Arc::get_mut(&mut pool.inner) {
            inner.tiering = Some(Arc::new(std::sync::Mutex::new(tiered)));
        }
        pool
    }

    #[must_use]
    /// docs
    pub fn queue(&self) -> &wgpu::Queue {
        &self.inner.queue
    }

    #[must_use]
    /// docs
    pub fn device(&self) -> &wgpu::Device {
        &self.inner.device
    }

    /// docs
    pub fn acquire(
        &self,
        len: u64,
        usage: wgpu::BufferUsages,
    ) -> Result<GpuBufferHandle, BackendError> {
        let allocation_len = size_class(len);
        let class_idx = class_index(allocation_len);
        let usage_kind = canonical_usage_kind(usage);

        // O(1) free-class search via trailing_zeros on the masked
        // non_empty_classes bitmap.  Within each size class we probe
        // only the sub-bucket that matches the canonical usage mask;
        // if that sub-bucket is empty we mask the class out and keep
        // scanning larger classes.  This eliminates the old "pop wrong
        // usage, push back, fall through to fresh alloc" path.
        let mut mask: u64 = if class_idx >= NUM_SIZE_CLASSES {
            0
        } else {
            !((1u64 << class_idx).wrapping_sub(1))
        };
        loop {
            let non_empty = self.inner.non_empty_classes.load(Ordering::Relaxed) & mask;
            if non_empty == 0 {
                break;
            }
            let idx = non_empty.trailing_zeros() as usize;
            if idx >= NUM_SIZE_CLASSES {
                break;
            }

            if let Some(entry) = self.inner.free[idx][usage_kind as usize].pop() {
                // V7-PERF-020: update tiering policy on hit.
                if let Some(tiering) = &self.inner.tiering {
                    let mut cache = tiering.lock().map_err(|_| {
                        BackendError::new(
                            "buffer pool tiering lock poisoned. Fix: recreate the WGPU backend before reusing the buffer pool.",
                        )
                    })?;
                    let key = Arc::as_ptr(&entry.buffer) as u64;
                    cache.record_access(key);
                }
                // Defensive: if the stored usage doesn't cover the request,
                // route it to its correct canonical sub-bucket rather than
                // leaving it stranded in the wrong queue (POOL-1 point 4).
                if !entry.usage.contains(usage) {
                    let correct_kind = canonical_usage_kind(entry.usage);
                    let correct_class = class_index(entry.allocation_len);
                    match self.inner.free[correct_class][correct_kind as usize].push(entry) {
                        Ok(()) => {
                            if correct_class != idx {
                                self.inner
                                    .non_empty_classes
                                    .fetch_or(1 << correct_class, Ordering::Relaxed);
                            }
                        }
                        Err(overflow) => {
                            tracing::warn!(
                                "buffer pool class {correct_class} usage bucket {correct_kind:?} is full while correcting a wrong-usage entry; dropping {} retained bytes. Fix: increase max_output_bytes or inspect usage canonicalization drift.",
                                overflow.allocation_len
                            );
                            self.inner
                                .stats
                                .retained_bytes
                                .fetch_sub(overflow.allocation_len as usize, Ordering::Relaxed);
                            self.inner.stats.evictions.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    mask &= !(1 << idx);
                    continue;
                }

                if self.inner.free[idx].iter().all(|q| q.is_empty()) {
                    self.inner
                        .non_empty_classes
                        .fetch_and(!(1 << idx), Ordering::Relaxed);
                }
                self.inner
                    .stats
                    .retained_bytes
                    .fetch_sub(entry.allocation_len as usize, Ordering::Relaxed);
                self.inner.stats.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(GpuBufferHandle::from_parts(
                    entry.buffer,
                    len,
                    entry.allocation_len,
                    entry.element_count,
                    entry.usage,
                    Some(self.pool_return()),
                ));
            }

            // Sub-bucket empty (lost race or genuinely empty).  Clear the
            // class bit only when *every* sub-bucket is empty so that other
            // usage kinds are not disturbed.
            if self.inner.free[idx].iter().all(|q| q.is_empty()) {
                self.inner
                    .non_empty_classes
                    .fetch_and(!(1 << idx), Ordering::Relaxed);
            }
            mask &= !(1 << idx);
        }

        let buffer = self.inner.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("vyre persistent pooled buffer"),
            size: allocation_len,
            usage,
            mapped_at_creation: false,
        });
        self.inner.stats.allocations.fetch_add(1, Ordering::Relaxed);
        Ok(GpuBufferHandle::from_parts(
            Arc::new(buffer),
            len,
            allocation_len,
            usize::try_from(len).unwrap_or(usize::MAX),
            usage,
            Some(self.pool_return()),
        ))
    }

    /// docs
    pub fn release(&self, handle: GpuBufferHandle) {
        drop(handle);
    }

    #[must_use]
    /// docs
    pub fn stats(&self) -> BufferPoolStats {
        BufferPoolStats {
            allocations: self.inner.stats.allocations.load(Ordering::Relaxed),
            hits: self.inner.stats.hits.load(Ordering::Relaxed),
            releases: self.inner.stats.releases.load(Ordering::Relaxed),
            evictions: self.inner.stats.evictions.load(Ordering::Relaxed),
            retained_bytes: self.inner.stats.retained_bytes.load(Ordering::Relaxed),
        }
    }

    fn pool_return(&self) -> PoolReturn {
        PoolReturn {
            inner: Arc::downgrade(&self.inner),
        }
    }
}

impl PoolReturn {
    pub(crate) fn release(
        self,
        buffer: Arc<wgpu::Buffer>,
        _byte_len: u64,
        allocation_len: u64,
        element_count: usize,
        usage: wgpu::BufferUsages,
    ) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let class_idx = class_index(allocation_len);
        let usage_kind = canonical_usage_kind(usage);

        // V7-PERF-019: update tiering policy on release
        if let Some(tiering) = &inner.tiering {
            let Ok(mut cache) = tiering.lock() else {
                tracing::error!(
                    "buffer pool tiering lock poisoned during release. Fix: recreate the WGPU backend before reusing the buffer pool."
                );
                return;
            };
            // wgpu::Buffer does not have global_id in VIR0.6 directly on Arc
            // but we can use the pointer address as a stable key for the process lifetime
            let key = Arc::as_ptr(&buffer) as u64;
            cache.record_access(key);
        }

        if inner.free[class_idx][usage_kind as usize]
            .push(FreeEntry {
                buffer,
                allocation_len,
                element_count,
                usage,
            })
            .is_ok()
        {
            inner
                .non_empty_classes
                .fetch_or(1 << class_idx, Ordering::Relaxed);
            inner.stats.releases.fetch_add(1, Ordering::Relaxed);
            inner
                .stats
                .retained_bytes
                .fetch_add(allocation_len as usize, Ordering::Relaxed);

            while inner.stats.retained_bytes.load(Ordering::Relaxed) > inner.max_retained_bytes {
                let mask = inner.non_empty_classes.load(Ordering::Relaxed);
                if mask == 0 {
                    break;
                }
                let highest_class = 63 - mask.leading_zeros() as usize;
                let mut evicted = None;
                for kind in 0..NUM_USAGE_KINDS {
                    if let Some(e) = inner.free[highest_class][kind].pop() {
                        evicted = Some(e);
                        break;
                    }
                }
                if let Some(evicted) = evicted {
                    inner
                        .stats
                        .retained_bytes
                        .fetch_sub(evicted.allocation_len as usize, Ordering::Relaxed);
                    inner.stats.evictions.fetch_add(1, Ordering::Relaxed);
                    if inner.free[highest_class].iter().all(|q| q.is_empty()) {
                        inner
                            .non_empty_classes
                            .fetch_and(!(1 << highest_class), Ordering::Relaxed);
                    }
                } else {
                    inner
                        .non_empty_classes
                        .fetch_and(!(1 << highest_class), Ordering::Relaxed);
                }
            }
        }
    }
}

fn size_class(len: u64) -> u64 {
    len.max(4).next_power_of_two()
}

fn class_index(len: u64) -> usize {
    len.max(4).trailing_zeros() as usize
}

#[cfg(test)]
mod tests {
    use super::BufferPool;
    use proptest::prelude::*;

    #[test]
    fn acquire_release_reuses_power_of_two_classes() {
        let arc = crate::runtime::cached_device()
            .expect("Fix: GPU device is required for persistent buffer pool test");
        let (device, queue) = &*arc;
        let config = vyre_driver::DispatchConfig::default();
        let pool = BufferPool::new(device.clone(), queue.clone(), &config);
        for len in 1..=1000 {
            let handle = pool
                .acquire(
                    len,
                    wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
                )
                .expect("Fix: pooled allocation should succeed");
            pool.release(handle);
        }
        assert!(
            pool.stats().allocations <= 16,
            "Fix: pool should allocate by power-of-two classes, stats={:?}",
            pool.stats()
        );
    }

    #[test]
    fn release_handles_tiering_lock_poison_without_panicking() {
        let arc = crate::runtime::cached_device()
            .expect("Fix: GPU device is required for persistent buffer pool test");
        let (device, queue) = &*arc;
        let config = vyre_driver::DispatchConfig::default();
        let pool = BufferPool::with_tiering(
            device.clone(),
            queue.clone(),
            &config,
            vec![crate::runtime::cache::CacheTier::new("hot", 1 << 20)],
        );
        let handle = pool
            .acquire(
                64,
                wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            )
            .expect("Fix: acquire before poisoning should succeed");
        let tiering = pool
            .inner
            .tiering
            .as_ref()
            .expect("Fix: with_tiering must attach a tiering policy")
            .clone();
        let poisoner = std::thread::spawn(move || {
            let _guard = tiering.lock().unwrap();
            panic!("intentional poison for buffer-pool release regression test");
        });
        assert!(
            poisoner.join().is_err(),
            "poisoning thread must panic to set lock state"
        );

        pool.release(handle);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn alternating_usage_hit_rate(
            sizes in prop::collection::vec(1u64..=65536, 20..=200),
        ) {
            let arc = crate::runtime::cached_device()
                .expect("Fix: GPU device is required for persistent buffer pool test");
            let (device, queue) = &*arc;
            let config = vyre_driver::DispatchConfig::default();
            let pool = BufferPool::new(device.clone(), queue.clone(), &config);

            let usage_a = wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST;
            let usage_b = wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_SRC
                | wgpu::BufferUsages::COPY_DST
                | wgpu::BufferUsages::INDIRECT;

            // Round 1: acquire alternating usages, then release everything.
            let mut handles = Vec::with_capacity(sizes.len());
            for (i, &len) in sizes.iter().enumerate() {
                let usage = if i % 2 == 0 { usage_a } else { usage_b };
                handles.push(pool.acquire(len, usage).unwrap());
            }
            for h in handles {
                pool.release(h);
            }

            let stats_after_first = pool.stats();
            prop_assert_eq!(
                stats_after_first.hits, 0,
                "first round should be 100% fresh allocations"
            );

            // Round 2: identical pattern.
            let mut handles = Vec::with_capacity(sizes.len());
            for (i, &len) in sizes.iter().enumerate() {
                let usage = if i % 2 == 0 { usage_a } else { usage_b };
                handles.push(pool.acquire(len, usage).unwrap());
            }
            for h in handles {
                pool.release(h);
            }

            let stats_after_second = pool.stats();
            let second_round_hits = stats_after_second.hits - stats_after_first.hits;
            let total = sizes.len();
            let hit_rate = second_round_hits as f64 / total as f64;
            prop_assert!(
                hit_rate >= 0.95,
                "second round hit rate should be >= 95%, got {:.2}% ({}/{}), stats={:?}",
                hit_rate * 100.0,
                second_round_hits,
                total,
                stats_after_second
            );
        }
    }
}
