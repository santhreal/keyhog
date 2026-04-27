//! Device-resident multi-file batch containers for the megakernel path.
//!
//! `FileBatch` packs many files into one contiguous haystack buffer,
//! uploads the prefix-sum offsets + metadata tables once, and keeps a
//! persistent device work queue + sparse hit ring alive across dispatches.

use crate::PipelineError;
use std::sync::Arc;
use vyre_driver_wgpu::buffer::GpuBufferHandle;

/// Number of `u32` words stored per file metadata record.
pub const FILE_METADATA_WORDS: usize = 4;
/// Number of `u32` words stored per work item.
pub const WORK_TRIPLE_WORDS: usize = 3;
/// Number of `u32` words stored per sparse hit record.
pub const HIT_RECORD_WORDS: usize = 4;
/// Number of control words stored in the persistent queue-state buffer.
pub const QUEUE_STATE_WORDS: usize = 5;
/// Maximum host work items accepted by one uploaded file batch.
pub const MAX_BATCH_WORK_ITEMS: usize = 16 * 1024 * 1024;
/// Maximum sparse hit records accepted by one uploaded file batch.
pub const MAX_BATCH_HIT_CAPACITY: u32 = 16 * 1024 * 1024;

/// Queue-state word indices.
pub mod queue_state_word {
    /// Next work-item index to claim.
    pub const HEAD: usize = 0;
    /// Total work items available in the queue.
    pub const QUEUE_LEN: usize = 1;
    /// Next sparse-hit slot to publish.
    pub const HIT_HEAD: usize = 2;
    /// Sparse-hit ring capacity.
    pub const HIT_CAPACITY: usize = 3;
    /// Total work items completed by the device.
    pub const DONE_COUNT: usize = 4;
}

/// Host-side file input for batch construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchFile {
    /// Stable hash of the file path.
    pub path_hash: u64,
    /// Decoded-layer index this file belongs to.
    pub decoded_layer_index: u32,
    /// Raw file bytes.
    pub bytes: Vec<u8>,
}

impl BatchFile {
    /// Build one batchable file record.
    #[must_use]
    pub fn new(path_hash: u64, decoded_layer_index: u32, bytes: Vec<u8>) -> Self {
        Self {
            path_hash,
            decoded_layer_index,
            bytes,
        }
    }
}

/// Per-file metadata mirrored into the device metadata table.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FileMetadata {
    /// Low 32 bits of the path hash.
    pub path_hash_lo: u32,
    /// High 32 bits of the path hash.
    pub path_hash_hi: u32,
    /// File byte length.
    pub size_bytes: u32,
    /// Decoded-layer index.
    pub decoded_layer_index: u32,
}

impl FileMetadata {
    fn from_file(file: &BatchFile) -> Result<Self, PipelineError> {
        Ok(Self {
            path_hash_lo: file.path_hash as u32,
            path_hash_hi: (file.path_hash >> 32) as u32,
            size_bytes: u32::try_from(file.bytes.len()).map_err(|_| PipelineError::QueueFull {
                queue: "submission",
                fix: "file size exceeds u32::MAX; split the batch into smaller files before megakernel batching",
            })?,
            decoded_layer_index: file.decoded_layer_index,
        })
    }
}

/// Device work item `(file_idx, rule_idx, layer_idx)`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct WorkTriple {
    /// File-table index.
    pub file_idx: u32,
    /// Rule-table index.
    pub rule_idx: u32,
    /// Decoded-layer index.
    pub layer_idx: u32,
}

impl WorkTriple {
    /// Build one queue entry.
    #[must_use]
    pub const fn new(file_idx: u32, rule_idx: u32, layer_idx: u32) -> Self {
        Self {
            file_idx,
            rule_idx,
            layer_idx,
        }
    }
}

/// Sparse hit emitted by the batched kernel.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct HitRecord {
    /// File-table index.
    pub file_idx: u32,
    /// Rule-table index.
    pub rule_idx: u32,
    /// Decoded-layer index.
    pub layer_idx: u32,
    /// Byte offset relative to the file start.
    pub match_offset: u32,
}

/// Persistent device-owned batch buffers.
#[derive(Clone)]
pub struct FileBatch {
    device_queue: Arc<(wgpu::Device, wgpu::Queue)>,
    file_metadata: Vec<FileMetadata>,
    file_offsets: Vec<u32>,
    work_items: Vec<WorkTriple>,
    hit_capacity: u32,
    haystack: GpuBufferHandle,
    offsets: GpuBufferHandle,
    metadata: GpuBufferHandle,
    work_queue: GpuBufferHandle,
    queue_state: GpuBufferHandle,
    hit_ring: GpuBufferHandle,
}

impl std::fmt::Debug for FileBatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileBatch")
            .field("file_count", &self.file_count())
            .field("work_items", &self.queue_len())
            .field("haystack_bytes", &self.haystack.byte_len())
            .field("hit_capacity", &self.hit_capacity)
            .finish()
    }
}

impl FileBatch {
    /// Upload a new multi-file batch into persistent GPU buffers.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::QueueFull`] when the batch exceeds the
    /// current `u32` table limits or the work queue would overflow.
    pub fn upload(
        device_queue: Arc<(wgpu::Device, wgpu::Queue)>,
        files: &[BatchFile],
        rule_count: u32,
        hit_capacity: u32,
    ) -> Result<Self, PipelineError> {
        validate_hit_capacity(hit_capacity)?;
        let (device, queue) = &*device_queue;
        let file_metadata = files
            .iter()
            .map(FileMetadata::from_file)
            .collect::<Result<Vec<_>, _>>()?;
        let file_offsets = build_offsets(files)?;
        let haystack_words = flatten_haystack_words(files)?;
        let work_items = build_work_queue(&file_metadata, rule_count)?;
        let queue_state_words = initial_queue_state(
            u32::try_from(work_items.len()).map_err(|_| PipelineError::QueueFull {
                queue: "submission",
                fix:
                    "work queue length exceeds u32::MAX; split the batch or reduce the rule fanout",
            })?,
            hit_capacity,
        );

        let haystack = GpuBufferHandle::upload(
            device,
            queue,
            bytemuck::cast_slice(&haystack_words),
            wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        )?;
        let offsets = GpuBufferHandle::upload(
            device,
            queue,
            bytemuck::cast_slice(&file_offsets),
            wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        )?;
        let metadata = GpuBufferHandle::upload(
            device,
            queue,
            bytemuck::cast_slice(&file_metadata),
            wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        )?;
        let work_queue = GpuBufferHandle::upload(
            device,
            queue,
            bytemuck::cast_slice(&work_items),
            wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        )?;
        let queue_state = GpuBufferHandle::upload(
            device,
            queue,
            bytemuck::cast_slice(&queue_state_words),
            wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        )?;
        let hit_ring = GpuBufferHandle::alloc(
            device,
            u64::from(hit_capacity) * (HIT_RECORD_WORDS as u64) * 4,
            wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_SRC
                | wgpu::BufferUsages::COPY_DST,
        )?;

        Ok(Self {
            device_queue,
            file_metadata,
            file_offsets,
            work_items,
            hit_capacity,
            haystack,
            offsets,
            metadata,
            work_queue,
            queue_state,
            hit_ring,
        })
    }

    /// Reset the persistent queue indices before another dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::Backend`] when the queue-state upload fails.
    pub fn reset_queue_state(&self) -> Result<(), PipelineError> {
        let (_, queue) = &*self.device_queue;
        let queue_len =
            u32::try_from(self.work_items.len()).map_err(|_| PipelineError::QueueFull {
                queue: "submission",
                fix:
                    "work queue length exceeds u32::MAX; split the batch or reduce the rule fanout",
            })?;
        let words = initial_queue_state(queue_len, self.hit_capacity);
        queue.write_buffer(self.queue_state.buffer(), 0, bytemuck::cast_slice(&words));
        Ok(())
    }

    /// Number of files in the batch.
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.file_metadata.len()
    }

    /// Number of queued `(file, rule, layer)` items.
    #[must_use]
    pub fn queue_len(&self) -> usize {
        self.work_items.len()
    }

    /// Sparse-hit capacity.
    #[must_use]
    pub const fn hit_capacity(&self) -> u32 {
        self.hit_capacity
    }

    /// Device queue used for every buffer in this batch.
    #[must_use]
    pub fn device_queue(&self) -> Arc<(wgpu::Device, wgpu::Queue)> {
        Arc::clone(&self.device_queue)
    }

    /// Packed haystack buffer.
    #[must_use]
    pub const fn haystack(&self) -> &GpuBufferHandle {
        &self.haystack
    }

    /// Prefix-sum offset table. Length = `file_count + 1`.
    #[must_use]
    pub const fn offsets(&self) -> &GpuBufferHandle {
        &self.offsets
    }

    /// Per-file metadata table.
    #[must_use]
    pub const fn metadata(&self) -> &GpuBufferHandle {
        &self.metadata
    }

    /// Persistent work queue of `(file_idx, rule_idx, layer_idx)` triples.
    #[must_use]
    pub const fn work_queue(&self) -> &GpuBufferHandle {
        &self.work_queue
    }

    /// Queue-state/control words.
    #[must_use]
    pub const fn queue_state(&self) -> &GpuBufferHandle {
        &self.queue_state
    }

    /// Sparse output ring.
    #[must_use]
    pub const fn hit_ring(&self) -> &GpuBufferHandle {
        &self.hit_ring
    }

    /// Host-side file metadata.
    #[must_use]
    pub fn host_metadata(&self) -> &[FileMetadata] {
        &self.file_metadata
    }

    /// Host-side prefix offsets.
    #[must_use]
    pub fn host_offsets(&self) -> &[u32] {
        &self.file_offsets
    }

    /// Host-side work queue.
    #[must_use]
    pub fn host_work_items(&self) -> &[WorkTriple] {
        &self.work_items
    }
}

fn build_offsets(files: &[BatchFile]) -> Result<Vec<u32>, PipelineError> {
    let mut offsets = Vec::with_capacity(files.len() + 1);
    offsets.push(0);
    let mut total = 0u64;
    for file in files {
        total = total
            .checked_add(file.bytes.len() as u64)
            .ok_or(PipelineError::QueueFull {
                queue: "submission",
                fix: "batched haystack length overflowed u64; split the batch into smaller shards",
            })?;
        offsets.push(u32::try_from(total).map_err(|_| PipelineError::QueueFull {
            queue: "submission",
            fix: "batched haystack exceeds u32::MAX bytes; split the batch into smaller shards",
        })?);
    }
    Ok(offsets)
}

fn flatten_haystack_words(files: &[BatchFile]) -> Result<Vec<u32>, PipelineError> {
    let total = files.iter().try_fold(0usize, |acc, file| {
        acc.checked_add(file.bytes.len())
            .ok_or(PipelineError::QueueFull {
                queue: "submission",
                fix:
                    "batched haystack length overflowed usize; split the batch into smaller shards",
            })
    })?;
    let mut words = Vec::with_capacity(total.div_ceil(4));
    let mut word = 0u32;
    let mut shift = 0u32;
    for file in files {
        for byte in &file.bytes {
            word |= u32::from(*byte) << shift;
            shift += 8;
            if shift == 32 {
                words.push(word);
                word = 0;
                shift = 0;
            }
        }
    }
    if shift != 0 {
        words.push(word);
    }
    if words.is_empty() {
        words.push(0);
    }
    Ok(words)
}

fn build_work_queue(
    file_metadata: &[FileMetadata],
    rule_count: u32,
) -> Result<Vec<WorkTriple>, PipelineError> {
    let capacity = file_metadata
        .len()
        .checked_mul(rule_count as usize)
        .ok_or(PipelineError::QueueFull {
        queue: "submission",
        fix: "file_count * rule_count overflowed usize; split the batch or reduce the rule fanout",
    })?;
    if capacity > u32::MAX as usize {
        return Err(PipelineError::QueueFull {
            queue: "submission",
            fix: "work queue length exceeds u32::MAX; split the batch or reduce the rule fanout before allocation",
        });
    }
    if capacity > MAX_BATCH_WORK_ITEMS {
        return Err(PipelineError::QueueFull {
            queue: "submission",
            fix: "work queue length exceeds the per-batch allocation cap; split the file batch or reduce the rule fanout before allocation",
        });
    }
    let mut work_items = Vec::with_capacity(capacity);
    for (file_idx, meta) in file_metadata.iter().enumerate() {
        let file_idx = u32::try_from(file_idx).map_err(|_| PipelineError::QueueFull {
            queue: "submission",
            fix: "file index exceeds u32::MAX; split the batch into smaller file shards",
        })?;
        for rule_idx in 0..rule_count {
            work_items.push(WorkTriple::new(
                file_idx,
                rule_idx,
                meta.decoded_layer_index,
            ));
        }
    }
    Ok(work_items)
}

fn validate_hit_capacity(hit_capacity: u32) -> Result<(), PipelineError> {
    if hit_capacity > MAX_BATCH_HIT_CAPACITY {
        return Err(PipelineError::QueueFull {
            queue: "submission",
            fix: "hit capacity exceeds the per-batch sparse ring cap; shard the batch or drain hits across multiple launches",
        });
    }
    Ok(())
}

fn initial_queue_state(queue_len: u32, hit_capacity: u32) -> [u32; QUEUE_STATE_WORDS] {
    [0, queue_len, 0, hit_capacity, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_are_prefix_sums() {
        let files = vec![
            BatchFile::new(1, 0, b"ab".to_vec()),
            BatchFile::new(2, 3, b"cdef".to_vec()),
        ];
        assert_eq!(build_offsets(&files).unwrap(), vec![0, 2, 6]);
    }

    #[test]
    fn work_queue_expands_files_x_rules() {
        let metadata = vec![
            FileMetadata {
                path_hash_lo: 1,
                path_hash_hi: 0,
                size_bytes: 2,
                decoded_layer_index: 4,
            },
            FileMetadata {
                path_hash_lo: 2,
                path_hash_hi: 0,
                size_bytes: 3,
                decoded_layer_index: 9,
            },
        ];
        let queue = build_work_queue(&metadata, 2).unwrap();
        assert_eq!(
            queue,
            vec![
                WorkTriple::new(0, 0, 4),
                WorkTriple::new(0, 1, 4),
                WorkTriple::new(1, 0, 9),
                WorkTriple::new(1, 1, 9),
            ]
        );
    }

    #[test]
    fn work_queue_rejects_u32_overflow_before_allocation() {
        let metadata = vec![
            FileMetadata {
                path_hash_lo: 1,
                path_hash_hi: 0,
                size_bytes: 1,
                decoded_layer_index: 0,
            },
            FileMetadata {
                path_hash_lo: 2,
                path_hash_hi: 0,
                size_bytes: 1,
                decoded_layer_index: 0,
            },
        ];
        let err = build_work_queue(&metadata, u32::MAX).expect_err(
            "Fix: queue fanout exceeding u32 protocol must be rejected before allocation",
        );
        assert!(matches!(err, PipelineError::QueueFull { .. }));
    }

    #[test]
    fn work_queue_rejects_allocation_cap_before_allocating() {
        let metadata = vec![
            FileMetadata {
                path_hash_lo: 1,
                path_hash_hi: 0,
                size_bytes: 1,
                decoded_layer_index: 0,
            };
            2
        ];
        let rule_count = u32::try_from(MAX_BATCH_WORK_ITEMS / metadata.len() + 1).unwrap();
        let err = build_work_queue(&metadata, rule_count)
            .expect_err("oversized work queue must reject before Vec allocation");
        assert!(matches!(err, PipelineError::QueueFull { .. }));
    }

    #[test]
    fn hit_capacity_rejects_allocation_cap() {
        let err = validate_hit_capacity(MAX_BATCH_HIT_CAPACITY + 1)
            .expect_err("oversized hit ring must reject before GPU allocation");
        assert!(matches!(err, PipelineError::QueueFull { .. }));
    }
}
