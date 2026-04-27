//! Reusable GPU buffer pool keyed by device, size class, and usage flags.

use crossbeam_queue::SegQueue;
use rustc_hash::FxHashMap;
use rustc_hash::FxHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, RwLock, Weak};

type LabelArc = Arc<str>;
use vyre_driver::error::{Error, Result};

const MAX_RETAINED_BUFFERS: usize = 4096;
const SHARD_COUNT: usize = 8;

#[derive(Clone, Hash, PartialEq, Eq)]
struct BufferKey {
    device: wgpu::Device,
    size_class: u64,
    usage_bits: u32,
}

#[derive(Default)]
struct BufferPoolInner {
    shards: [Shard; SHARD_COUNT],
    next_id: AtomicU64,
    retained: AtomicUsize,
}

struct Shard {
    queues: RwLock<FxHashMap<BufferKey, Arc<SegQueue<CachedBuffer>>>>,
}

impl Default for Shard {
    fn default() -> Self {
        Self {
            queues: RwLock::new(FxHashMap::default()),
        }
    }
}

struct CachedBuffer {
    id: u64,
    buffer: wgpu::Buffer,
}

/// Device-aware reusable GPU buffer pool.
#[derive(Clone, Default)]
pub struct BufferPool {
    inner: Arc<BufferPoolInner>,
}

/// Buffer handle that returns to its originating [`BufferPool`] on drop.
pub struct PooledBuffer {
    key: BufferKey,
    id: u64,
    /// Pool tracing label — `Arc<str>` so hot-path acquire does not
    /// allocate a fresh `String` per handle (PERF-HOT-34).
    label: LabelArc,
    buffer: Option<wgpu::Buffer>,
    pool: Weak<BufferPoolInner>,
}

/// Error returned when a pooled buffer handle no longer owns its GPU buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferPoolError {
    label: String,
}

impl std::fmt::Display for BufferPoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pooled buffer `{}` no longer owns its inner wgpu::Buffer. Fix: do not access a PooledBuffer after it has been released to the pool.",
            self.label
        )
    }
}

impl std::error::Error for BufferPoolError {}

impl BufferPoolError {
    fn released(label: &str) -> Self {
        Self {
            label: label.to_string(),
        }
    }
}

impl From<BufferPoolError> for Error {
    fn from(error: BufferPoolError) -> Self {
        Self::Gpu {
            message: error.to_string(),
        }
    }
}

impl BufferPool {
    /// Return the process-wide buffer pool.
    #[must_use]
    #[inline]
    pub fn global() -> &'static Self {
        static POOL: LazyLock<BufferPool> = LazyLock::new(BufferPool::new);
        &POOL
    }

    /// Create an empty buffer pool.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(BufferPoolInner::default()),
        }
    }

    /// Acquire a reusable buffer with at least `size` bytes and exactly `usage`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Gpu`] when pool metadata cannot be locked.
    #[inline]
    pub fn acquire(
        &self,
        device: &wgpu::Device,
        label: &str,
        size: u64,
        usage: wgpu::BufferUsages,
    ) -> Result<PooledBuffer> {
        let key = BufferKey {
            device: device.clone(),
            size_class: size_class(size),
            usage_bits: usage.bits(),
        };
        let queue = self.inner.queue_for(&key);
        let reusable = queue.pop();

        let (id, buffer) = if let Some(entry) = reusable {
            self.inner.retained.fetch_sub(1, Ordering::Relaxed);
            (entry.id, entry.buffer)
        } else {
            let new_id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
            let b = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some(label),
                size: key.size_class,
                usage,
                mapped_at_creation: false,
            });
            (new_id, b)
        };
        Ok(PooledBuffer {
            key,
            id,
            label: label.into(),
            buffer: Some(buffer),
            pool: Arc::downgrade(&self.inner),
        })
    }

    /// Release a buffer to the pool immediately.
    #[inline]
    pub fn release(&self, buffer: PooledBuffer) {
        drop(buffer);
    }

    /// Acquire a buffer for the duration of `f` and release it afterward.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Gpu`] when buffer acquisition fails.
    #[inline]
    pub fn with_buffer<R>(
        &self,
        device: &wgpu::Device,
        label: &str,
        size: u64,
        usage: wgpu::BufferUsages,
        f: impl FnOnce(&wgpu::Buffer) -> R,
    ) -> Result<R> {
        let buffer = self.acquire(device, label, size, usage)?;
        let result = f(buffer.buffer()?);
        self.release(buffer);
        Ok(result)
    }
}

impl PooledBuffer {
    /// Return the size-class allocation backing this pooled buffer.
    #[must_use]
    #[inline]
    pub fn size(&self) -> u64 {
        self.key.size_class
    }

    /// Return the unique ID backing this pooled buffer allocation.
    #[must_use]
    #[inline]
    pub fn buffer_id(&self) -> u64 {
        self.id
    }

    /// Return the inner `wgpu::Buffer`.
    #[inline]
    pub fn buffer(&self) -> std::result::Result<&wgpu::Buffer, BufferPoolError> {
        self.buffer
            .as_ref()
            .ok_or_else(|| BufferPoolError::released(self.label.as_ref()))
    }
}

// Intentionally no Deref or AsRef impl — callers must use `buffer()` which
// returns `Result<&wgpu::Buffer, BufferPoolError>` so that double-use or
// use-after-release produces a structured error instead of a panic.
//
// SAFE-05: Removing Deref prevents implicit panics in method dispatch.

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        let Some(buffer) = self.buffer.take() else {
            return;
        };
        let Some(pool) = self.pool.upgrade() else {
            return;
        };
        let mut retained = pool.retained.load(Ordering::Relaxed);
        loop {
            if retained >= MAX_RETAINED_BUFFERS {
                return;
            }
            match pool.retained.compare_exchange_weak(
                retained,
                retained + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => retained = current,
            }
        }
        pool.queue_for(&self.key).push(CachedBuffer {
            id: self.id,
            buffer,
        });
    }
}

impl BufferPoolInner {
    fn queue_for(&self, key: &BufferKey) -> Arc<SegQueue<CachedBuffer>> {
        let shard = &self.shards[shard_index(key)];
        if let Some(queue) = shard
            .queues
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
        {
            return Arc::clone(queue);
        }
        let mut queues = shard.queues.write().unwrap_or_else(|e| e.into_inner());
        Arc::clone(
            queues
                .entry(key.clone())
                .or_insert_with(|| Arc::new(SegQueue::new())),
        )
    }
}

fn size_class(size: u64) -> u64 {
    size.max(wgpu::COPY_BUFFER_ALIGNMENT)
        .next_multiple_of(wgpu::COPY_BUFFER_ALIGNMENT)
}

fn shard_index(key: &BufferKey) -> usize {
    let mut hasher = FxHasher::default();
    key.hash(&mut hasher);
    let hash = hasher.finish();
    ((hash ^ (hash >> 1) ^ (hash >> 2)) as usize) & (SHARD_COUNT - 1)
}

#[cfg(test)]
mod tests {
    use super::size_class;
    use crate::runtime::cached_device;

    #[test]
    fn size_class_is_copy_aligned_and_nonzero() {
        assert_eq!(size_class(0), wgpu::COPY_BUFFER_ALIGNMENT);
        assert_eq!(size_class(1), wgpu::COPY_BUFFER_ALIGNMENT);
        assert_eq!(
            size_class(wgpu::COPY_BUFFER_ALIGNMENT + 1),
            (wgpu::COPY_BUFFER_ALIGNMENT + 1).next_multiple_of(wgpu::COPY_BUFFER_ALIGNMENT)
        );
    }

    #[test]
    fn buffer_returns_err_after_drop() {
        let device_queue =
            cached_device().expect("Fix: GPU device is required for buffer pool regression test");
        let mut pooled = super::BufferPool::global()
            .acquire(
                &device_queue.0,
                "released-buffer-regression",
                4,
                wgpu::BufferUsages::COPY_DST,
            )
            .expect("Fix: buffer acquisition should succeed");

        let _released = pooled.buffer.take();
        let err = pooled
            .buffer()
            .expect_err("released handle must not expose a buffer");
        assert!(err.to_string().contains("released-buffer-regression"));
    }
}
