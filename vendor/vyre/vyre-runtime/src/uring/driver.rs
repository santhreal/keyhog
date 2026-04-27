//! End-to-end ingest driver: file/NVMe -> io_uring -> mapped slot -> io_queue.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;

use crate::megakernel::MegakernelIoQueue;
use crate::PipelineError;

#[cfg(feature = "uring-cmd-nvme")]
use super::gpudirect::encode_nvme_read_sqe;
use super::gpudirect::GpuDirectCapability;
use super::stream::{AsyncUringStream, GpuMappedBuffer, Iovec};

#[derive(Debug)]
struct PendingIngest {
    _file: Option<File>,
    tag: u32,
    completion: PendingCompletion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "uring-cmd-nvme"), allow(dead_code))]
enum PendingCompletion {
    ByteCountFromCqe,
    NativeNvmeStatus { expected_byte_count: u32 },
}

/// Host-visible completion surfaced once the DMA lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompletedIngest {
    /// Queue slot that completed.
    pub slot: u32,
    /// Number of bytes the kernel reported as transferred.
    pub byte_count: u32,
    /// Caller-defined tag mirrored into the `io_queue`.
    pub tag: u32,
}

/// Native-read strategy used by [`NvmeGpuIngestDriver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeReadPath {
    /// `IORING_OP_READ_FIXED` into a registered GPU-visible mapping.
    ///
    /// This removes the userspace bounce buffer but still uses normal file
    /// reads submitted by the CPU. It is the compatibility path for filesystems
    /// and GPU memory APIs that do not expose BAR1 peer DMA.
    RegisteredMappedRead,
    /// `IORING_OP_URING_CMD` NVMe read into BAR1 peer memory.
    ///
    /// This is the canonical native ingest path: CPU submits one NVMe command,
    /// the device DMAs bytes directly into GPU-owned memory, and the megakernel
    /// consumes the published slot.
    GpuDirectNvmePassthrough,
}

/// Wire the Linux ingest loop end-to-end without userspace bounce buffers.
pub struct NvmeGpuIngestDriver<'a> {
    stream: AsyncUringStream<'a>,
    mapped_slots: Vec<GpuMappedBuffer<'a>>,
    registered_iovecs: Vec<Iovec>,
    megakernel_io_queue: MegakernelIoQueue,
    pending: Vec<Option<PendingIngest>>,
    slot_bytes: usize,
    read_path: NativeReadPath,
}

impl<'a> NvmeGpuIngestDriver<'a> {
    /// Split one mapped staging buffer into `slot_count` fixed-size slots and
    /// register those slots for `IORING_OP_READ_FIXED`.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::QueueFull`] when the buffer cannot be evenly
    /// partitioned into non-empty slots, or an io_uring syscall error if
    /// buffer registration fails.
    pub fn new(
        stream: AsyncUringStream<'a>,
        slot_count: u32,
        megakernel_io_queue: MegakernelIoQueue,
    ) -> Result<Self, PipelineError> {
        Self::new_with_path(
            stream,
            slot_count,
            megakernel_io_queue,
            NativeReadPath::RegisteredMappedRead,
        )
    }

    /// Construct a driver that requires native GPUDirect NVMe passthrough.
    ///
    /// This constructor fails loudly when `uring-cmd-nvme` is not compiled in
    /// or `nvidia-fs` is not active. Callers that need the VYRE canonical path
    /// should use this instead of [`NvmeGpuIngestDriver::new`].
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::NvmePassthroughDisabled`] when the feature is
    /// absent, [`PipelineError::Backend`] when the host probe rejects
    /// GPUDirect, or the same slot-partitioning errors as
    /// [`NvmeGpuIngestDriver::new`].
    pub fn new_gpudirect(
        stream: AsyncUringStream<'a>,
        slot_count: u32,
        megakernel_io_queue: MegakernelIoQueue,
    ) -> Result<Self, PipelineError> {
        match GpuDirectCapability::probe() {
            GpuDirectCapability::Available { .. } => Self::new_with_path(
                stream,
                slot_count,
                megakernel_io_queue,
                NativeReadPath::GpuDirectNvmePassthrough,
            ),
            GpuDirectCapability::FeatureDisabled => Err(PipelineError::NvmePassthroughDisabled),
            GpuDirectCapability::Unavailable { reason } => Err(PipelineError::Backend(format!(
                "GPUDirect native read unavailable: {reason}. Fix: install/enable nvidia-fs, use a BAR1-backed GpuMappedBuffer, or use NvmeGpuIngestDriver::new for registered mapped reads."
            ))),
        }
    }

    fn new_with_path(
        stream: AsyncUringStream<'a>,
        slot_count: u32,
        megakernel_io_queue: MegakernelIoQueue,
        read_path: NativeReadPath,
    ) -> Result<Self, PipelineError> {
        if slot_count == 0 {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "NvmeGpuIngestDriver requires at least one slot",
            });
        }
        let total_len = stream.gpu_buffer.len();
        let slot_bytes = total_len / slot_count as usize;
        if slot_bytes == 0 || slot_bytes * slot_count as usize > total_len {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix:
                    "mapped staging buffer is too small to partition into the requested slot count",
            });
        }

        let mut mapped_slots = Vec::with_capacity(slot_count as usize);
        let mut registered_iovecs = Vec::with_capacity(slot_count as usize);
        for slot in 0..slot_count as usize {
            let offset = slot * slot_bytes;
            let slot_buffer = stream.gpu_buffer.sub_region(offset, slot_bytes)?;
            registered_iovecs.push(Iovec {
                iov_base: slot_buffer.as_ptr().cast(),
                iov_len: slot_buffer.len(),
            });
            mapped_slots.push(slot_buffer);
        }
        Ok(Self {
            stream,
            mapped_slots,
            registered_iovecs,
            megakernel_io_queue,
            pending: std::iter::repeat_with(|| None)
                .take(slot_count as usize)
                .collect(),
            slot_bytes,
            read_path,
        })
    }

    /// Read an entire file into a fixed ingest slot.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::QueueFull`] when the slot is already in
    /// flight or the file is larger than the slot capacity.
    pub fn submit_file(&mut self, path: &Path, slot: u32) -> Result<(), PipelineError> {
        let slot_usize = self.validate_slot_for_submit(slot)?;

        let file = File::open(path).map_err(|error| {
            PipelineError::Backend(format!("open {} failed: {error}", path.display()))
        })?;
        let file_len = file
            .metadata()
            .map_err(|error| {
                PipelineError::Backend(format!("stat {} failed: {error}", path.display()))
            })?
            .len();
        if file_len > self.slot_bytes as u64 {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "file exceeds the configured ingest slot size; enlarge the mapped staging buffer or segment the file",
            });
        }

        let target_offset = (slot_usize * self.slot_bytes) as u64;
        let slot_iovec = &mut self.registered_iovecs[slot_usize..slot_usize + 1];
        // SAFETY: `slot_iovec` and file descriptor stay live until the CQE is reaped.
        unsafe {
            self.stream.submit_read_to_gpu_at(
                file.as_raw_fd(),
                0,
                file_len as u32,
                target_offset,
                slot_iovec,
            )?;
        }
        self.pending[slot_usize] = Some(PendingIngest {
            _file: Some(file),
            tag: slot,
            completion: PendingCompletion::ByteCountFromCqe,
        });
        Ok(())
    }

    /// Submit one native NVMe read directly into the mapped slot.
    ///
    /// `nvme_fd` must name an NVMe character device such as `/dev/ng0n1`.
    /// `mapped_slots[slot]` must be a BAR1 peer-memory region created with
    /// [`GpuMappedBuffer::from_bar1_peer_with_owner`]. On completion the slot is
    /// published to the megakernel `io_queue`; the CPU does not copy bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::NvmePassthroughDisabled`] when the build lacks
    /// native NVMe passthrough support, [`PipelineError::QueueFull`] when the
    /// slot or byte range is invalid, or [`PipelineError::Backend`] when this
    /// driver was constructed for the compatibility path.
    ///
    /// # Safety
    ///
    /// The caller must ensure `nvme_fd`, `namespace_id`, `starting_lba`, and
    /// `blocks` describe a valid device range, and that the mapped slot remains
    /// a valid peer-DMA destination until its CQE is reaped.
    #[cfg(feature = "uring-cmd-nvme")]
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn submit_native_nvme_read(
        &mut self,
        nvme_fd: i32,
        namespace_id: u32,
        starting_lba: u64,
        blocks: u32,
        bytes_per_block: u32,
        slot: u32,
    ) -> Result<(), PipelineError> {
        if self.read_path != NativeReadPath::GpuDirectNvmePassthrough {
            return Err(PipelineError::Backend(
                "native NVMe read submitted on a registered-mapped-read driver. Fix: construct with NvmeGpuIngestDriver::new_gpudirect and a BAR1-backed GpuMappedBuffer.".to_string(),
            ));
        }
        let slot_usize = self.validate_slot_for_submit(slot)?;
        if blocks == 0 || bytes_per_block == 0 {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "native NVMe reads require non-zero block count and bytes_per_block",
            });
        }
        let byte_count = blocks
            .checked_mul(bytes_per_block)
            .ok_or(PipelineError::QueueFull {
                queue: "submission",
                fix: "native NVMe read byte count overflowed u32; submit a smaller range",
            })?;
        if byte_count as usize > self.slot_bytes {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "native NVMe read exceeds the configured ingest slot size; enlarge the BAR1 mapped slot or submit fewer blocks",
            });
        }

        let dest = self.mapped_slots[slot_usize].as_ptr() as u64;
        let sqe = encode_nvme_read_sqe(namespace_id, starting_lba, blocks, dest);
        let user_data = (slot_usize * self.slot_bytes) as u64;
        // SAFETY: forwarded from this method's contract; the SQE is built
        // from validated scalar fields and a slot-local BAR1 destination.
        unsafe {
            self.stream
                .submit_nvme_passthrough(nvme_fd, user_data, &sqe)?;
        }
        self.pending[slot_usize] = Some(PendingIngest {
            _file: None,
            tag: slot,
            completion: PendingCompletion::NativeNvmeStatus {
                expected_byte_count: byte_count,
            },
        });
        Ok(())
    }

    /// Disabled-feature variant of [`NvmeGpuIngestDriver::submit_native_nvme_read`].
    ///
    /// # Errors
    ///
    /// Always returns [`PipelineError::NvmePassthroughDisabled`].
    ///
    /// # Safety
    ///
    /// This method does not touch `nvme_fd`; it exists to keep the public API
    /// structured across feature sets.
    #[cfg(not(feature = "uring-cmd-nvme"))]
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn submit_native_nvme_read(
        &mut self,
        _nvme_fd: i32,
        _namespace_id: u32,
        _starting_lba: u64,
        _blocks: u32,
        _bytes_per_block: u32,
        _slot: u32,
    ) -> Result<(), PipelineError> {
        Err(PipelineError::NvmePassthroughDisabled)
    }

    /// Flush submissions, reap CQEs, and publish the completed slots into the
    /// megakernel `io_queue`.
    pub fn poll_completions(&mut self) -> Result<Vec<CompletedIngest>, PipelineError> {
        self.stream.flush_submissions()?;
        let mut completed = Vec::new();
        let mut first_error: Option<PipelineError> = None;

        while let Some(cqe) = self.stream.ring_state.peek_cqe() {
            let res = cqe.res;
            let slot = (cqe.user_data as usize) / self.slot_bytes.max(1);
            self.stream.ring_state.advance_cq();
            self.stream.inflight = self.stream.inflight.saturating_sub(1);

            let pending = self.pending.get_mut(slot).and_then(Option::take);
            if res < 0 {
                if first_error.is_none() {
                    first_error = Some(PipelineError::IoUringSyscall {
                        syscall: "io_uring_cqe",
                        errno: -res,
                        fix: "inspect the offending file descriptor and slot metadata; common causes are EIO on disk or EFAULT on an invalid registered buffer",
                    });
                }
                continue;
            }

            let pending = match pending {
                Some(pending) => pending,
                None => {
                    if first_error.is_none() {
                        first_error = Some(PipelineError::Backend(format!(
                            "CQE for slot {slot} arrived without matching pending metadata"
                        )));
                    }
                    continue;
                }
            };
            let byte_count = match pending.completion {
                PendingCompletion::ByteCountFromCqe => res as u32,
                PendingCompletion::NativeNvmeStatus {
                    expected_byte_count,
                } => {
                    if res != 0 {
                        if first_error.is_none() {
                            first_error = Some(PipelineError::Backend(format!(
                                "NVMe passthrough completion for slot {slot} returned non-zero status {res}. Fix: inspect namespace id, LBA range, permissions, and nvidia-fs state."
                            )));
                        }
                        continue;
                    }
                    expected_byte_count
                }
            };
            self.megakernel_io_queue.publish_slot(
                slot as u32,
                slot as u32,
                byte_count,
                pending.tag,
            )?;
            completed.push(CompletedIngest {
                slot: slot as u32,
                byte_count,
                tag: pending.tag,
            });
        }

        match first_error {
            Some(err) => Err(err),
            None => Ok(completed),
        }
    }

    /// Borrow the raw io_queue bytes for backend upload/readback.
    #[must_use]
    pub fn megakernel_io_queue(&self) -> &MegakernelIoQueue {
        &self.megakernel_io_queue
    }

    /// Mutable access to the io_queue bytes.
    #[must_use]
    pub fn megakernel_io_queue_mut(&mut self) -> &mut MegakernelIoQueue {
        &mut self.megakernel_io_queue
    }

    /// Fixed slot size in bytes.
    #[must_use]
    pub fn slot_bytes(&self) -> usize {
        self.slot_bytes
    }

    /// Number of registered slots.
    #[must_use]
    pub fn slot_count(&self) -> usize {
        self.registered_iovecs.len()
    }

    /// Read path this driver was constructed to use.
    #[must_use]
    pub fn read_path(&self) -> NativeReadPath {
        self.read_path
    }

    fn validate_slot_for_submit(&self, slot: u32) -> Result<usize, PipelineError> {
        let slot_usize = slot as usize;
        if slot_usize >= self.mapped_slots.len() {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "slot exceeds the configured mapped-slot count",
            });
        }
        if self.pending[slot_usize].is_some() {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "slot already has an in-flight ingest; drain completions before reusing it",
            });
        }
        Ok(slot_usize)
    }
}
