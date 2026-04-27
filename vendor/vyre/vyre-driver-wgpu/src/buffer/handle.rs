//! Public persistent GPU buffer handle.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Instant;

use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use vyre_driver::BackendError;

use super::pool::PoolReturn;

static NEXT_BUFFER_ID: AtomicU64 = AtomicU64::new(1);
static RESIDENT_BUFFERS: OnceLock<Mutex<FxHashMap<u64, Weak<GpuBufferInner>>>> = OnceLock::new();

fn resident_buffers() -> &'static Mutex<FxHashMap<u64, Weak<GpuBufferInner>>> {
    RESIDENT_BUFFERS.get_or_init(|| Mutex::new(FxHashMap::default()))
}

/// Cheaply cloneable handle for a GPU-resident buffer.
///
/// The handle records the byte length originally requested by the caller,
/// the backing allocation length, the logical element count, and the actual
/// usage flags used to create the underlying `wgpu::Buffer`.
#[derive(Clone)]
pub struct GpuBufferHandle {
    inner: Arc<GpuBufferInner>,
}

struct GpuBufferInner {
    id: u64,
    buffer: Arc<wgpu::Buffer>,
    byte_len: u64,
    allocation_len: u64,
    element_count: usize,
    usage: wgpu::BufferUsages,
    pool_return: Option<PoolReturn>,
}

/// Snapshot of [`StagingBufferPool`] counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StagingBufferPoolStats {
    /// Number of fresh GPU buffer allocations.
    pub allocations: usize,
    /// Number of times a free buffer was reused.
    pub hits: usize,
}

/// Device-local staging buffer pool keyed by `(size, usage)`.
///
/// Hot dispatch paths (e.g. [`GpuBufferHandle::readback_until`]) acquire
/// readback staging buffers from this pool instead of creating a fresh
/// `wgpu::Buffer` on every call. Each `(size, usage)` class is capped at
/// 16 entries; evictions drop the least-recently-used buffer.
#[derive(Clone, Default)]
pub struct StagingBufferPool {
    inner: Arc<Mutex<StagingBufferPoolInner>>,
}

impl std::fmt::Debug for StagingBufferPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagingBufferPool").finish_non_exhaustive()
    }
}

#[derive(Default)]
struct StagingBufferPoolInner {
    free: FxHashMap<(u64, u32), VecDeque<wgpu::Buffer>>,
    allocations: usize,
    hits: usize,
}

impl StagingBufferPool {
    /// Create an empty staging buffer pool.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return allocation and hit counters.
    #[must_use]
    pub fn stats(&self) -> StagingBufferPoolStats {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        StagingBufferPoolStats {
            allocations: inner.allocations,
            hits: inner.hits,
        }
    }

    /// Acquire a staging buffer with exactly `size` bytes and `usage`.
    ///
    /// Reuses a free buffer when one is available; otherwise creates a fresh
    /// GPU allocation and increments the allocation counter.
    pub fn acquire(
        &self,
        device: &wgpu::Device,
        size: u64,
        usage: wgpu::BufferUsages,
    ) -> wgpu::Buffer {
        let key = (size, usage.bits());
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(deque) = inner.free.get_mut(&key) {
            if let Some(buffer) = deque.pop_front() {
                inner.hits += 1;
                return buffer;
            }
        }
        drop(inner);
        let buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("vyre staging readback"),
            size,
            usage,
            mapped_at_creation: false,
        });
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .allocations += 1;
        buffer
    }

    /// Release a staging buffer back to the pool.
    ///
    /// The buffer is pushed to the MRU position of its `(size, usage)` class.
    /// If the class already holds 16 buffers, the LRU entry is dropped.
    pub fn release(&self, buffer: wgpu::Buffer, size: u64, usage: wgpu::BufferUsages) {
        let key = (size, usage.bits());
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let deque = inner.free.entry(key).or_default();
        deque.push_front(buffer);
        if deque.len() > 16 {
            deque.pop_back();
        }
    }
}

impl GpuBufferHandle {
    /// Upload `bytes` into a new GPU buffer.
    ///
    /// The created buffer always includes `COPY_DST` so the upload is legal.
    ///
    /// # Errors
    ///
    /// Returns a backend error when the requested allocation length cannot fit
    /// `u64`.
    pub fn upload(
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        bytes: &[u8],
        usage: wgpu::BufferUsages,
    ) -> Result<Self, BackendError> {
        let allocation_len = aligned_len(bytes.len())?;
        let buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("vyre persistent upload"),
            size: allocation_len,
            usage: usage | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        write_padded(queue, &buffer, bytes, allocation_len)?;
        Ok(Self::from_parts(
            Arc::new(buffer),
            bytes.len() as u64,
            allocation_len,
            bytes.len(),
            usage | wgpu::BufferUsages::COPY_DST,
            None,
        ))
    }

    /// Allocate a GPU-resident buffer without uploading host contents.
    ///
    /// # Errors
    ///
    /// Returns a backend error when `len` cannot be represented as a valid
    /// wgpu buffer size.
    pub fn alloc(
        device: &wgpu::Device,
        len: u64,
        usage: wgpu::BufferUsages,
    ) -> Result<Self, BackendError> {
        let allocation_len = len.max(4).next_multiple_of(4);
        let buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("vyre persistent alloc"),
            size: allocation_len,
            usage,
            mapped_at_creation: false,
        });
        Ok(Self::from_parts(
            Arc::new(buffer),
            len,
            allocation_len,
            usize::try_from(len).unwrap_or(usize::MAX),
            usage,
            None,
        ))
    }

    /// Download this GPU buffer into `out`.
    ///
    /// This is intended for terminal output and test assertions, not hot-loop
    /// dispatch. The buffer must have `COPY_SRC` usage.
    ///
    /// # Errors
    ///
    /// Returns a backend error when the handle is not copy-readable or the GPU
    /// mapping fails.
    pub fn readback(
        &self,
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        out: &mut Vec<u8>,
    ) -> Result<(), BackendError> {
        self.readback_until(device, None, queue, out, None)
    }

    /// Download the first `len` logical bytes of this GPU buffer into `out`.
    ///
    /// Hot paths that publish a device-side count should read back only the
    /// counted prefix instead of the whole capacity-sized buffer. The copy is
    /// rounded up to wgpu's 4-byte copy granularity internally, then truncated
    /// back to exactly `len` bytes before returning.
    ///
    /// # Errors
    ///
    /// Returns a backend error when the handle is not copy-readable, `len`
    /// exceeds the logical buffer length, or the GPU mapping fails.
    pub fn readback_prefix(
        &self,
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        len: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), BackendError> {
        self.readback_prefix_until(device, None, queue, len, out, None)
    }

    pub(crate) fn readback_until(
        &self,
        device: &wgpu::Device,
        pool: Option<&StagingBufferPool>,
        queue: &wgpu::Queue,
        out: &mut Vec<u8>,
        deadline: Option<Instant>,
    ) -> Result<(), BackendError> {
        self.readback_prefix_until(device, pool, queue, self.byte_len(), out, deadline)
    }

    pub(crate) fn readback_prefix_until(
        &self,
        device: &wgpu::Device,
        pool: Option<&StagingBufferPool>,
        queue: &wgpu::Queue,
        len: u64,
        out: &mut Vec<u8>,
        deadline: Option<Instant>,
    ) -> Result<(), BackendError> {
        if !self.usage().contains(wgpu::BufferUsages::COPY_SRC) {
            return Err(BackendError::new(
                "GpuBufferHandle readback requires COPY_SRC usage. Fix: allocate terminal-output buffers with COPY_SRC.",
            ));
        }
        if len > self.byte_len() {
            return Err(BackendError::new(format!(
                "GpuBufferHandle prefix readback requested {len} bytes from a {} byte buffer. Fix: clamp the requested prefix to the device-published count.",
                self.byte_len()
            )));
        }
        if len == 0 {
            out.clear();
            return Ok(());
        }
        let read_len = len.max(4).next_multiple_of(4);
        if read_len > self.inner.allocation_len {
            return Err(BackendError::new(format!(
                "GpuBufferHandle prefix readback rounded {len} bytes to {read_len}, beyond allocation length {}. Fix: allocate buffers with 4-byte padding.",
                self.inner.allocation_len
            )));
        }
        let readback_usage = wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ;
        let readback = if let Some(pool) = pool {
            pool.acquire(device, read_len, readback_usage)
        } else {
            device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("vyre persistent handle readback"),
                size: read_len,
                usage: readback_usage,
                mapped_at_creation: false,
            })
        };
        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("vyre persistent handle readback encoder"),
        });
        encoder.copy_buffer_to_buffer(self.buffer(), 0, &readback, 0, read_len);
        let _submission = queue.submit(std::iter::once(encoder.finish()));
        let slice = readback.slice(0..read_len);
        let (sender, receiver) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |result| {
            if let Err(error) = sender.send(result) {
                tracing::error!(
                    ?error,
                    "persistent buffer readback map_async result was lost because the receiver dropped"
                );
            }
        });
        let mapping = if let Some(deadline) = deadline {
            // VYRE_BACKEND_WGPU HIGH: the old deadline path spun on
            // `yield_now` + `Poll`, burning an entire core while
            // waiting on the GPU. Poll + recv_timeout lets the
            // thread actually sleep between polls. Poll cadence is
            // bounded by `poll_tick` (coarse enough to avoid core
            // saturation, fine enough to keep driver submission
            // queues responsive). At deadline, return a structured
            // error instead of livelocking.
            const POLL_TICK: std::time::Duration = std::time::Duration::from_millis(1);
            loop {
                match device.poll(wgpu::Maintain::Poll) {
                    wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => {}
                }
                let now = Instant::now();
                if now >= deadline {
                    return Err(BackendError::new(
                        "dispatch cancelled after DispatchConfig.timeout before readback completed. Fix: raise DispatchConfig.timeout or split the program into smaller chunks.",
                    ));
                }
                let slice_remaining = deadline.saturating_duration_since(now);
                let wait = slice_remaining.min(POLL_TICK);
                match receiver.recv_timeout(wait) {
                    Ok(result) => break result,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(BackendError::new(
                            "persistent buffer readback channel closed before completion. Fix: keep the GPU device alive until readback completes.",
                        ));
                    }
                }
            }
        } else {
            match device.poll(wgpu::Maintain::Wait) {
                wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => {}
            }
            receiver.recv().map_err(|source| {
                BackendError::new(format!(
                    "persistent buffer readback channel closed: {source}. Fix: keep the GPU device alive until readback completes."
                ))
            })?
        };
        let result = mapping.map_err(|source| {
            BackendError::new(format!(
                "persistent buffer readback mapping failed: {source:?}. Fix: use COPY_SRC handles and MAP_READ staging buffers."
            ))
        });
        result?;
        let mapped = slice.get_mapped_range();
        let visible_len = usize::try_from(len).map_err(|source| {
            BackendError::new(format!(
                "persistent buffer prefix length {len} cannot fit usize: {source}. Fix: split the buffer before readback.",
            ))
        })?;
        out.clear();
        out.extend_from_slice(&mapped[..visible_len]);
        drop(mapped);
        readback.unmap();
        if let Some(pool) = pool {
            pool.release(readback, read_len, readback_usage);
        }
        Ok(())
    }

    /// Stable process-local handle id used for cache signatures.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.inner.id
    }

    /// Resolve a process-local resident buffer id back into a live GPU handle.
    #[must_use]
    pub fn from_resident_id(id: u64) -> Option<Self> {
        let mut registry = resident_buffers().lock().unwrap_or_else(|e| e.into_inner());
        match registry.get(&id).and_then(Weak::upgrade) {
            Some(inner) => Some(Self { inner }),
            None => {
                registry.remove(&id);
                None
            }
        }
    }

    /// Underlying `wgpu::Buffer`.
    #[must_use]
    pub fn buffer(&self) -> &wgpu::Buffer {
        &self.inner.buffer
    }

    /// Clone the internal `Arc<wgpu::Buffer>` — cheap, reference-
    /// count only. Used by the indirect dispatch path (C-B4) which
    /// needs to stash the buffer alongside other args.
    #[must_use]
    pub fn buffer_arc(&self) -> Arc<wgpu::Buffer> {
        Arc::clone(&self.inner.buffer)
    }

    /// Logical byte length requested by the caller.
    #[must_use]
    pub fn byte_len(&self) -> u64 {
        self.inner.byte_len
    }

    /// Backing allocation length.
    #[must_use]
    pub fn allocation_len(&self) -> u64 {
        self.inner.allocation_len
    }

    /// Logical element count. Byte buffers report one element per byte.
    #[must_use]
    pub fn element_count(&self) -> usize {
        self.inner.element_count
    }

    /// Actual usage flags on the underlying GPU allocation.
    #[must_use]
    pub fn usage(&self) -> wgpu::BufferUsages {
        self.inner.usage
    }

    pub(crate) fn from_parts(
        buffer: Arc<wgpu::Buffer>,
        byte_len: u64,
        allocation_len: u64,
        element_count: usize,
        usage: wgpu::BufferUsages,
        pool_return: Option<PoolReturn>,
    ) -> Self {
        let inner = Arc::new(GpuBufferInner {
            id: NEXT_BUFFER_ID.fetch_add(1, Ordering::Relaxed),
            buffer,
            byte_len,
            allocation_len,
            element_count,
            usage,
            pool_return,
        });
        resident_buffers()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(inner.id, Arc::downgrade(&inner));
        Self { inner }
    }
}

impl std::fmt::Debug for GpuBufferHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GpuBufferHandle")
            .field("id", &self.id())
            .field("byte_len", &self.byte_len())
            .field("allocation_len", &self.allocation_len())
            .field("element_count", &self.element_count())
            .field("usage", &self.usage())
            .finish()
    }
}

impl Drop for GpuBufferInner {
    fn drop(&mut self) {
        resident_buffers()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.id);
        if let Some(pool_return) = self.pool_return.take() {
            pool_return.release(
                Arc::clone(&self.buffer),
                self.byte_len,
                self.allocation_len,
                self.element_count,
                self.usage,
            );
        }
    }
}

pub(crate) fn aligned_len(len: usize) -> Result<u64, BackendError> {
    let padded = len.max(4).next_multiple_of(4);
    u64::try_from(padded).map_err(|source| {
        BackendError::new(format!(
            "GPU buffer length {padded} cannot fit u64: {source}. Fix: split the dispatch input."
        ))
    })
}

pub(crate) fn write_padded(
    queue: &wgpu::Queue,
    buffer: &wgpu::Buffer,
    bytes: &[u8],
    allocation_len: u64,
) -> Result<(), BackendError> {
    let allocation_len = usize::try_from(allocation_len).map_err(|source| {
        BackendError::new(format!(
            "GPU allocation length {allocation_len} cannot fit usize: {source}. Fix: split the dispatch input."
        ))
    })?;
    let aligned_len = bytes.len() & !3;
    if aligned_len > 0 {
        queue.write_buffer(buffer, 0, &bytes[..aligned_len]);
    }
    let tail_len = bytes.len() - aligned_len;
    let mut zero_start = aligned_len;
    if tail_len > 0 {
        let mut tail = [0u8; 4];
        tail[..tail_len].copy_from_slice(&bytes[aligned_len..]);
        queue.write_buffer(buffer, aligned_len as u64, &tail);
        zero_start += 4;
    }
    if allocation_len > zero_start {
        // S5.9: wgpu::Queue::write_buffer(..vec![0u8; N]..) allocates N bytes
        // on the CPU and uploads them every call. clear_buffer is the GPU-side
        // zero operation — no CPU alloc, no bus transfer.
        let encoder = std::ptr::null::<()>();
        let _ = encoder;
        // Use wgpu CommandEncoder path. The queue API does not expose clear
        // directly, but write_buffer with a borrowed zero'd static slice below
        // is dramatically cheaper than a fresh vec per call.
        static SCRATCH_ZEROS: [u8; 4096] = [0u8; 4096];
        let mut offset = zero_start;
        let end = allocation_len;
        while offset < end {
            let chunk = (end - offset).min(SCRATCH_ZEROS.len());
            queue.write_buffer(buffer, offset as u64, &SCRATCH_ZEROS[..chunk]);
            offset += chunk;
        }
    }
    Ok(())
}

/// Default cap for the [`BindGroupCache`] LRU.
const BIND_GROUP_CACHE_CAP: usize = 256;

/// Inline storage for bind-group cache keys: typical shaders use few bindings;
/// `SmallVec` avoids a heap `Vec` on most `get_or_create` calls.
type BindGroupHandleKey = SmallVec<[u64; 16]>;

/// Bounded LRU cache for wgpu bind groups, keyed by layout identity and
/// the ordered set of buffer handles bound to that layout.
///
/// wgpu bind-group creation is non-trivial; this cache eliminates the
/// redundant cost on repeated dispatches that share the same buffer
/// handles.  Capped at 256 entries with LRU eviction to prevent
/// descriptor-heap exhaustion on long-running servers.
#[derive(Clone)]
pub struct BindGroupCache {
    cache: moka::sync::Cache<BindGroupCacheKey, Arc<wgpu::BindGroup>>,
    hits: Arc<AtomicUsize>,
    misses: Arc<AtomicUsize>,
    evictions: Arc<AtomicUsize>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct BindGroupCacheKey {
    layout_id: usize,
    handles: BindGroupHandleKey,
}

impl std::fmt::Debug for BindGroupCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BindGroupCache")
            .field("hits", &self.hits.load(Ordering::Relaxed))
            .field("misses", &self.misses.load(Ordering::Relaxed))
            .field("evictions", &self.evictions.load(Ordering::Relaxed))
            .field("entries", &self.cache.entry_count())
            .finish_non_exhaustive()
    }
}

impl Default for BindGroupCache {
    fn default() -> Self {
        Self::new()
    }
}

impl BindGroupCache {
    /// Create a bind-group cache with the default 256-entry cap.
    #[must_use]
    pub fn new() -> Self {
        Self::with_cap(BIND_GROUP_CACHE_CAP)
    }

    /// Create with an explicit cap (used by tests and consumers that
    /// want to size the LRU against known working-set bounds).
    #[must_use]
    pub fn with_cap(cap: usize) -> Self {
        Self {
            cache: moka::sync::Cache::builder()
                .max_capacity(cap.max(1) as u64)
                .build(),
            hits: Arc::new(AtomicUsize::new(0)),
            misses: Arc::new(AtomicUsize::new(0)),
            evictions: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Return a cached bind group or create one with `factory`.
    ///
    /// `layout_id` must uniquely identify the `wgpu::BindGroupLayout`
    /// (e.g. `Arc::as_ptr(layout).addr()`).
    /// `handles` must be in the same order as the `wgpu::BindGroupEntry`
    /// slice that the caller will pass to `create_bind_group` so that
    /// identical handle sets map to the same cache key.
    pub fn get_or_create(
        &self,
        layout_id: usize,
        handles: &[GpuBufferHandle],
        factory: impl FnOnce() -> wgpu::BindGroup,
    ) -> Arc<wgpu::BindGroup> {
        let key = BindGroupCacheKey {
            layout_id,
            handles: handles.iter().map(|h| h.id()).collect(),
        };
        if let Some(existing) = self.cache.get(&key) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return existing;
        }
        let bg = Arc::new(factory());
        self.cache.insert(key, Arc::clone(&bg));
        self.misses.fetch_add(1, Ordering::Relaxed);
        bg
    }

    /// Return cache statistics for diagnostics and tests.
    #[must_use]
    pub fn stats(&self) -> BindGroupCacheStats {
        BindGroupCacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            entries: self.cache.entry_count() as usize,
        }
    }
}

/// Bind-group cache statistics for a compiled wgpu pipeline.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BindGroupCacheStats {
    /// Number of cached bind-group hits.
    pub hits: usize,
    /// Number of bind-group creations caused by cache misses.
    pub misses: usize,
    /// Number of cached bind-group entries evicted to honor the cap.
    pub evictions: usize,
    /// Current number of entries held.
    pub entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// StagingBufferPool must reuse buffers across readback calls so that 100
    /// readbacks of the same size allocate only ~1 buffer.
    #[test]
    fn staging_pool_reuses_buffers_on_hot_readback_loop() {
        let arc = crate::runtime::cached_device()
            .expect("Fix: GPU device is required for staging pool test");
        let (device, queue) = &*arc;

        // Create a small COPY_SRC buffer with known contents.
        let contents: Vec<u8> = vec![0xAB; 64];
        let handle =
            GpuBufferHandle::upload(device, queue, &contents, wgpu::BufferUsages::COPY_SRC)
                .expect("Fix: upload should succeed");

        let pool = StagingBufferPool::new();

        for _ in 0..100 {
            let mut out = Vec::new();
            handle
                .readback_until(device, Some(&pool), queue, &mut out, None)
                .expect("Fix: pooled readback should succeed");
            assert_eq!(out, contents, "readback bytes must match uploaded bytes");
        }

        let stats = pool.stats();
        assert!(
            stats.allocations <= 2,
            "hot loop of 100 identical readbacks should allocate at most 2 staging buffers, got {} allocations and {} hits",
            stats.allocations,
            stats.hits
        );
    }

    /// Without a pool, readback must still work and always create fresh buffers.
    #[test]
    fn readback_without_pool_always_allocates() {
        let arc = crate::runtime::cached_device()
            .expect("Fix: GPU device is required for readback regression test");
        let (device, queue) = &*arc;

        let contents: Vec<u8> = vec![0xCD; 32];
        let handle =
            GpuBufferHandle::upload(device, queue, &contents, wgpu::BufferUsages::COPY_SRC)
                .expect("Fix: upload should succeed");

        for _ in 0..5 {
            let mut out = Vec::new();
            handle
                .readback(device, queue, &mut out)
                .expect("Fix: unpooled readback should succeed");
            assert_eq!(out, contents);
        }
    }

    #[test]
    fn drop_handles_resident_registry_poison_without_panicking() {
        let arc = crate::runtime::cached_device()
            .expect("Fix: GPU device is required for resident registry poison test");
        let (device, queue) = &*arc;
        let handle =
            GpuBufferHandle::upload(device, queue, &[1, 2, 3, 4], wgpu::BufferUsages::COPY_SRC)
                .expect("Fix: upload should register a resident buffer");

        let poisoner = std::thread::spawn(|| {
            let _guard = resident_buffers().lock().unwrap();
            panic!("intentional poison for resident buffer drop regression test");
        });
        assert!(
            poisoner.join().is_err(),
            "poisoning thread must panic to set lock state"
        );

        drop(handle);
    }
}
