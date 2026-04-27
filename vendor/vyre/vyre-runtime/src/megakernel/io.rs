//! IO subsystem — GPU↔Host DMA request queue for the persistent megakernel.
//!
//! The GPU kernel writes DMA requests into an `io_queue` ring buffer.
//! A host-side pump thread polls the queue, services requests via
//! io_uring (Linux) or standard file I/O (portable), and writes
//! completion flags back. This eliminates userspace bounce buffers on the
//! hot path. Compatibility reads land in registered GPU-visible memory;
//! native NVMe passthrough lands directly in BAR1 GPU memory.
//!
//! ## Protocol
//!
//! Each IO slot is 8 × u32 words:
//! ```text
//! [op_type, src_handle, dst_handle, offset_lo, offset_hi, byte_count, status, tag]
//! ```
//!
//! The GPU CAS-claims slots like the work ring, but uses the io_queue
//! buffer. The host polls `status` for REQUEST and services the DMA.

use super::protocol::slot;
use crate::PipelineError;
use std::sync::atomic::{fence, Ordering};
use vyre_foundation::ir::{Expr, Node};

/// Number of u32 words per IO queue slot.
pub const IO_SLOT_WORDS: u32 = 8;

/// Default number of IO queue slots.
pub const IO_SLOT_COUNT: u32 = 64;

/// Resource table name used for resolving IO source handles.
pub const IO_SOURCE_CAPABILITY_TABLE: &str = "io_source_capability_table";

/// Resource table name used for resolving IO destination handles.
pub const IO_DESTINATION_CAPABILITY_TABLE: &str = "io_destination_capability_table";

/// Async stream tag used by megakernel IO DMA requests.
pub const IO_QUEUE_DMA_TAG: &str = "io_queue_dma";

/// Word offsets within an IO slot.
pub mod io_word {
    /// DMA operation type (see [`IoOp`]).
    pub const OP_TYPE: u32 = 0;
    /// Source buffer handle id.
    pub const SRC_HANDLE: u32 = 1;
    /// Destination buffer handle id.
    pub const DST_HANDLE: u32 = 2;
    /// Byte offset into source (low 32 bits).
    pub const OFFSET_LO: u32 = 3;
    /// Byte offset into source (high 32 bits, for >4GB transfers).
    pub const OFFSET_HI: u32 = 4;
    /// Number of bytes to transfer.
    pub const BYTE_COUNT: u32 = 5;
    /// Slot status — same semantics as work ring (EMPTY/PUBLISHED/CLAIMED/DONE).
    pub const STATUS: u32 = 6;
    /// Caller-supplied tag for correlating completions.
    pub const TAG: u32 = 7;
}

/// IO operation types.
pub mod io_op {
    /// Read from storage into GPU buffer.
    pub const READ: u32 = 0x01;
    /// Write from GPU buffer to storage.
    pub const WRITE: u32 = 0x02;
    /// Memory fence — ensure all prior IO ops are visible.
    pub const FENCE: u32 = 0x03;
}

/// IO completion status codes written by the host pump.
pub mod io_status {
    /// Operation completed successfully.
    pub const OK: u32 = 0x10;
    /// Operation failed — error code in the tag word.
    pub const ERROR: u32 = 0x11;
}

/// Host-side IO request decoded from the io_queue buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoRequest {
    /// Slot index in the io_queue.
    pub slot_idx: u32,
    /// Operation type.
    pub op_type: u32,
    /// Source buffer handle.
    pub src_handle: u32,
    /// Destination buffer handle.
    pub dst_handle: u32,
    /// 64-bit byte offset into source.
    pub offset: u64,
    /// Byte count to transfer.
    pub byte_count: u32,
    /// Caller tag.
    pub tag: u32,
}

/// Host-side completion record published into `io_queue` for a mapped
/// ingest slot the GPU can consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoCompletion {
    /// Queue slot index.
    pub slot_idx: u32,
    /// Mapped ingest slot id / destination handle.
    pub mapped_slot: u32,
    /// Number of bytes now valid in the mapped slot.
    pub byte_count: u32,
    /// Caller-defined completion tag.
    pub tag: u32,
}

/// Host-side half of the 64-slot `io_queue` ring the megakernel polls.
#[derive(Debug, Clone)]
pub struct MegakernelIoQueue {
    words: Vec<u32>,
    slot_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IoQueueView {
    slot_count: usize,
}

impl MegakernelIoQueue {
    /// Allocate an empty queue with `slot_count` entries.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::QueueFull`] when `slot_count` is zero or
    /// exceeds the IR/program's fixed poll window of [`IO_SLOT_COUNT`].
    pub fn new(slot_count: u32) -> Result<Self, PipelineError> {
        if slot_count == 0 {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "MegakernelIoQueue requires at least one slot",
            });
        }
        if slot_count > IO_SLOT_COUNT {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "MegakernelIoQueue exceeds the compiled IO poll window of 64 slots; enlarge IO_SLOT_COUNT and rebuild the megakernel before publishing more than 64 completions",
            });
        }
        let word_count = slot_count
            .checked_mul(IO_SLOT_WORDS)
            .ok_or(PipelineError::QueueFull {
                queue: "submission",
                fix: "io_queue word count overflows u32; shard the queue before allocating",
            })?;
        Ok(Self {
            words: vec![0; word_count as usize],
            slot_count,
        })
    }

    /// Borrow the raw bytes for backend upload / readback.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::cast_slice(&self.words)
    }

    /// Mutably borrow the raw bytes for backend upload / host updates.
    #[must_use]
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        bytemuck::cast_slice_mut(&mut self.words)
    }

    /// Queue capacity in slots.
    #[must_use]
    pub fn slot_count(&self) -> u32 {
        self.slot_count
    }

    /// Publish a completed DMA slot so the megakernel can consume it.
    ///
    /// The host writes the metadata first, then flips `STATUS` to
    /// `slot::PUBLISHED` as the publication barrier.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::QueueFull`] when the slot is out of bounds or
    /// still owned by the GPU/host from a prior ingest.
    pub fn publish_slot(
        &mut self,
        queue_slot: u32,
        mapped_slot: u32,
        byte_count: u32,
        tag: u32,
    ) -> Result<(), PipelineError> {
        if queue_slot >= self.slot_count {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "io_queue slot exceeds MegakernelIoQueue::slot_count; enlarge the queue or publish into a valid slot id",
            });
        }
        let current_status = self.read_word(queue_slot, io_word::STATUS);
        if current_status != slot::EMPTY {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "io_queue slot still in flight; wait for the GPU to recycle it before publishing again",
            });
        }
        self.write_word(queue_slot, io_word::OP_TYPE, io_op::READ);
        self.write_word(queue_slot, io_word::SRC_HANDLE, 0);
        self.write_word(queue_slot, io_word::DST_HANDLE, mapped_slot);
        self.write_word(queue_slot, io_word::OFFSET_LO, 0);
        self.write_word(queue_slot, io_word::OFFSET_HI, 0);
        self.write_word(queue_slot, io_word::BYTE_COUNT, byte_count);
        self.write_word(queue_slot, io_word::TAG, tag);

        fence(Ordering::Release);
        self.write_word(queue_slot, io_word::STATUS, slot::PUBLISHED);
        Ok(())
    }

    /// Read the queue slot back as a completion record.
    #[must_use]
    pub fn completion(&self, queue_slot: u32) -> Option<IoCompletion> {
        if queue_slot >= self.slot_count {
            return None;
        }
        let status = self.read_word(queue_slot, io_word::STATUS);
        if status == slot::EMPTY {
            return None;
        }
        Some(IoCompletion {
            slot_idx: queue_slot,
            mapped_slot: self.read_word(queue_slot, io_word::DST_HANDLE),
            byte_count: self.read_word(queue_slot, io_word::BYTE_COUNT),
            tag: self.read_word(queue_slot, io_word::TAG),
        })
    }

    /// Return true when the GPU has recycled the slot to `EMPTY`.
    #[must_use]
    pub fn is_recycled(&self, queue_slot: u32) -> bool {
        if queue_slot >= self.slot_count {
            return false;
        }
        let status = self.read_word(queue_slot, io_word::STATUS);
        match status {
            slot::EMPTY => true,
            slot::PUBLISHED | slot::CLAIMED | io_status::OK | io_status::ERROR | slot::DONE => {
                false
            }
            _ => false,
        }
    }

    fn read_word(&self, slot_idx: u32, word: u32) -> u32 {
        let idx = queue_word_index(slot_idx, word);
        let value = self.words[idx];
        fence(Ordering::Acquire);
        value
    }

    fn write_word(&mut self, slot_idx: u32, word: u32, value: u32) {
        let idx = queue_word_index(slot_idx, word);
        self.words[idx] = value;
        fence(Ordering::Release);
    }
}

/// Strictly poll the io_queue buffer for pending requests.
///
/// # Errors
///
/// Returns [`PipelineError`] when the byte view is not 4-byte aligned,
/// contains a partial IO slot, or exceeds the compiled poll window.
pub fn try_poll_io_requests(io_queue_bytes: &[u8]) -> Result<Vec<IoRequest>, PipelineError> {
    let view = validate_io_queue_view(io_queue_bytes.len())?;
    let mut requests = Vec::with_capacity(view.slot_count);

    for slot_idx in 0..view.slot_count {
        let base = slot_idx * IO_SLOT_WORDS as usize;
        let read_word = |offset: u32| -> u32 {
            let off = (base + offset as usize) * 4;
            let bytes: [u8; 4] = io_queue_bytes[off..off + 4]
                .try_into()
                .expect("Fix: IO queue validation guarantees whole u32 words");
            fence(Ordering::Acquire);
            u32::from_le_bytes(bytes)
        };

        let status = read_word(io_word::STATUS);
        if status == slot::PUBLISHED {
            let offset_lo = read_word(io_word::OFFSET_LO);
            let offset_hi = read_word(io_word::OFFSET_HI);
            requests.push(IoRequest {
                slot_idx: slot_idx as u32,
                op_type: read_word(io_word::OP_TYPE),
                src_handle: read_word(io_word::SRC_HANDLE),
                dst_handle: read_word(io_word::DST_HANDLE),
                offset: ((offset_hi as u64) << 32) | (offset_lo as u64),
                byte_count: read_word(io_word::BYTE_COUNT),
                tag: read_word(io_word::TAG),
            });
        }
    }

    Ok(requests)
}

/// Poll the io_queue buffer for pending requests.
///
/// The host pump should service each request and then call
/// [`complete_io_request`] to write the completion status back.
///
/// # Errors
///
/// Returns [`PipelineError`] when the byte view is not 4-byte aligned,
/// contains a partial IO slot, or exceeds the compiled poll window.
pub fn poll_io_requests(io_queue_bytes: &[u8]) -> Result<Vec<IoRequest>, PipelineError> {
    try_poll_io_requests(io_queue_bytes)
}

/// Strictly write a completion status for a serviced IO request.
///
/// # Errors
///
/// Returns [`PipelineError`] when the target slot is outside the queue byte
/// view, the view is not aligned to complete IO slots, or the view exceeds the
/// compiled poll window.
pub fn try_complete_io_request(
    io_queue_bytes: &mut [u8],
    slot_idx: u32,
    success: bool,
) -> Result<(), PipelineError> {
    let view = validate_io_queue_view(io_queue_bytes.len())?;
    if slot_idx as usize >= view.slot_count {
        return Err(PipelineError::QueueFull {
            queue: "submission",
            fix: "io_queue completion slot exceeds queue length; complete a valid slot id",
        });
    }
    let base = (slot_idx as usize) * (IO_SLOT_WORDS as usize) * 4;
    let status_off = base + (io_word::STATUS as usize) * 4;
    let status = if success {
        io_status::OK
    } else {
        io_status::ERROR
    };
    fence(Ordering::Release);
    io_queue_bytes[status_off..status_off + 4].copy_from_slice(&status.to_le_bytes());
    Ok(())
}

/// Write a completion status for a serviced IO request.
///
/// # Errors
///
/// Returns [`PipelineError`] when the target slot is outside the queue byte
/// view, the view is not aligned to complete IO slots, or the view exceeds the
/// compiled poll window.
pub fn complete_io_request(
    io_queue_bytes: &mut [u8],
    slot_idx: u32,
    success: bool,
) -> Result<(), PipelineError> {
    try_complete_io_request(io_queue_bytes, slot_idx, success)
}

/// Validate that a caller-owned IO queue byte buffer matches the megakernel
/// IO-slot ABI without allocating or polling it.
///
/// # Errors
///
/// Returns [`PipelineError`] when the byte view is not 4-byte aligned,
/// contains a partial IO slot, or exceeds the compiled poll window.
pub fn validate_io_queue_bytes(io_queue_bytes: &[u8]) -> Result<(), PipelineError> {
    validate_io_queue_view(io_queue_bytes.len()).map(|_| ())
}

/// Strictly encode an empty IO queue buffer.
///
/// # Errors
///
/// Returns [`PipelineError::QueueFull`] when `slot_count` is zero, exceeds
/// the compiled megakernel poll window, or overflows the host byte length.
pub fn try_encode_empty_io_queue(slot_count: u32) -> Result<Vec<u8>, PipelineError> {
    if slot_count == 0 {
        return Err(PipelineError::QueueFull {
            queue: "submission",
            fix: "io_queue requires at least one slot",
        });
    }
    if slot_count > IO_SLOT_COUNT {
        return Err(PipelineError::QueueFull {
            queue: "submission",
            fix: "io_queue exceeds the compiled IO poll window of 64 slots; enlarge IO_SLOT_COUNT and rebuild the megakernel before encoding a larger queue",
        });
    }
    let word_count = slot_count
        .checked_mul(IO_SLOT_WORDS)
        .ok_or(PipelineError::QueueFull {
            queue: "submission",
            fix: "io_queue word count overflows u32; shard the queue before encoding",
        })?;
    let byte_count = usize::try_from(word_count)
        .ok()
        .and_then(|words| words.checked_mul(4))
        .ok_or(PipelineError::QueueFull {
            queue: "submission",
            fix: "io_queue byte count overflows usize; shard the queue before encoding",
        })?;
    Ok(vec![0u8; byte_count])
}

/// Encode an empty IO queue buffer.
///
/// # Errors
///
/// Returns [`PipelineError::QueueFull`] when `slot_count` is zero, exceeds
/// the compiled megakernel poll window, or overflows the host byte length.
pub fn encode_empty_io_queue(slot_count: u32) -> Result<Vec<u8>, PipelineError> {
    try_encode_empty_io_queue(slot_count)
}

fn queue_word_index(slot_idx: u32, word: u32) -> usize {
    slot_idx as usize * IO_SLOT_WORDS as usize + word as usize
}

fn validate_io_queue_view(byte_len: usize) -> Result<IoQueueView, PipelineError> {
    if byte_len % 4 != 0 {
        return Err(PipelineError::Backend(format!(
            "io_queue has {byte_len} bytes, which is not 4-byte aligned. Fix: pass a whole u32 queue buffer."
        )));
    }
    let slot_bytes = (IO_SLOT_WORDS as usize)
        .checked_mul(4)
        .ok_or(PipelineError::QueueFull {
            queue: "submission",
            fix: "io_queue slot byte width overflows usize; keep IO_SLOT_WORDS within the u32 ABI",
        })?;
    if byte_len % slot_bytes != 0 {
        return Err(PipelineError::Backend(format!(
            "io_queue has {byte_len} bytes, which is not a multiple of slot size {slot_bytes}. Fix: pass whole IO slots."
        )));
    }
    let slot_count = byte_len / slot_bytes;
    if slot_count > IO_SLOT_COUNT as usize {
        return Err(PipelineError::QueueFull {
            queue: "submission",
            fix: "io_queue byte view exceeds the compiled IO poll window of 64 slots; split the queue or rebuild the megakernel with a larger IO_SLOT_COUNT",
        });
    }
    Ok(IoQueueView { slot_count })
}

/// Build the GPU-side IO poll body as `Vec<Node>` for composition
/// into the megakernel persistent loop.
///
/// Each iteration, the kernel scans IO slots for DONE status
/// (set by the host) and reads the completion result. This is
/// the GPU's "interrupt handler" for asynchronous DMA.
#[must_use]
pub fn io_completion_poll_body() -> Vec<Node> {
    vec![Node::loop_for(
        "io_poll_idx",
        Expr::u32(0),
        Expr::u32(IO_SLOT_COUNT),
        vec![
            Node::let_bind(
                "io_poll_base",
                Expr::mul(Expr::var("io_poll_idx"), Expr::u32(IO_SLOT_WORDS)),
            ),
            Node::let_bind(
                "io_poll_status",
                Expr::load(
                    "io_queue",
                    Expr::add(Expr::var("io_poll_base"), Expr::u32(io_word::STATUS)),
                ),
            ),
            // If host marked OK, clear the slot for reuse.
            // If ERROR, preserve it for telemetry/host debugging.
            Node::if_then(
                Expr::eq(Expr::var("io_poll_status"), Expr::u32(io_status::OK)),
                vec![Node::store(
                    "io_queue",
                    Expr::add(Expr::var("io_poll_base"), Expr::u32(io_word::STATUS)),
                    Expr::u32(slot::EMPTY),
                )],
            ),
        ],
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_io_queue_has_no_requests() {
        let buf = encode_empty_io_queue(4).unwrap();
        let reqs = poll_io_requests(&buf).expect("empty aligned queue must poll");
        assert!(reqs.is_empty());
    }

    #[test]
    fn published_io_slot_is_detected() {
        let mut buf = encode_empty_io_queue(4).unwrap();
        // Publish slot 1: READ, src=5, dst=6, offset=0x1000, count=4096, tag=42
        let base = IO_SLOT_WORDS as usize * 4;
        let write_word = |buf: &mut Vec<u8>, word: u32, val: u32| {
            let off = base + word as usize * 4;
            buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
        };
        write_word(&mut buf, io_word::OP_TYPE, io_op::READ);
        write_word(&mut buf, io_word::SRC_HANDLE, 5);
        write_word(&mut buf, io_word::DST_HANDLE, 6);
        write_word(&mut buf, io_word::OFFSET_LO, 0x1000);
        write_word(&mut buf, io_word::OFFSET_HI, 0);
        write_word(&mut buf, io_word::BYTE_COUNT, 4096);
        write_word(&mut buf, io_word::STATUS, slot::PUBLISHED);
        write_word(&mut buf, io_word::TAG, 42);

        let reqs = poll_io_requests(&buf).expect("published aligned queue must poll");
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].slot_idx, 1);
        assert_eq!(reqs[0].op_type, io_op::READ);
        assert_eq!(reqs[0].offset, 0x1000);
        assert_eq!(reqs[0].byte_count, 4096);
    }

    #[test]
    fn complete_sets_status() {
        let mut buf = encode_empty_io_queue(2).unwrap();
        complete_io_request(&mut buf, 0, true).expect("valid completion slot must update");
        let status_off = io_word::STATUS as usize * 4;
        let status = u32::from_le_bytes(buf[status_off..status_off + 4].try_into().unwrap());
        assert_eq!(status, io_status::OK);
    }

    #[test]
    fn io_completion_poll_produces_valid_ir() {
        let nodes = io_completion_poll_body();
        assert_eq!(nodes.len(), 1); // one loop_for
    }

    #[test]
    fn host_publish_slot_round_trips() {
        let mut queue = MegakernelIoQueue::new(4).unwrap();
        assert_eq!(queue.as_bytes().as_ptr() as usize % 4, 0);
        queue.publish_slot(2, 7, 4096, 99).unwrap();
        let completion = queue.completion(2).expect("published slot present");
        assert_eq!(completion.mapped_slot, 7);
        assert_eq!(completion.byte_count, 4096);
        assert_eq!(completion.tag, 99);
        assert_eq!(
            u32::from_le_bytes(
                queue.as_bytes()[((2 * IO_SLOT_WORDS + io_word::STATUS) as usize * 4)
                    ..((2 * IO_SLOT_WORDS + io_word::STATUS) as usize * 4 + 4)]
                    .try_into()
                    .unwrap()
            ),
            slot::PUBLISHED
        );
    }

    #[test]
    fn host_queue_byte_view_stays_aligned_after_mutation() {
        let mut queue = MegakernelIoQueue::new(IO_SLOT_COUNT).unwrap();
        assert_eq!(queue.as_mut_bytes().as_ptr() as usize % 4, 0);
        queue.publish_slot(0, 3, 512, 77).unwrap();
        assert_eq!(queue.as_bytes().as_ptr() as usize % 4, 0);
    }

    #[test]
    fn oversized_queue_is_rejected_with_actionable_error() {
        let error = MegakernelIoQueue::new(IO_SLOT_COUNT + 1)
            .expect_err("queues larger than the compiled 64-slot poll window must fail");
        match error {
            PipelineError::QueueFull { fix, .. } => {
                assert!(
                    fix.contains("64 slots"),
                    "overflow error must explain the compiled queue limit, got `{fix}`"
                );
            }
            other => panic!("expected QueueFull overflow error, got {other:?}"),
        }
    }

    #[test]
    fn publishing_the_sixty_fifth_completion_errors_instead_of_dropping() {
        let mut queue = MegakernelIoQueue::new(IO_SLOT_COUNT).unwrap();
        for slot in 0..IO_SLOT_COUNT {
            queue.publish_slot(slot, slot, 4096, slot).unwrap();
            let base = (slot * IO_SLOT_WORDS + io_word::STATUS) as usize * 4;
            queue.as_mut_bytes()[base..base + 4].copy_from_slice(&io_status::OK.to_le_bytes());
        }

        let error = queue
            .publish_slot(IO_SLOT_COUNT, IO_SLOT_COUNT, 4096, IO_SLOT_COUNT)
            .expect_err("the 65th published completion must fail loudly");
        match error {
            PipelineError::QueueFull { fix, .. } => {
                assert!(
                    fix.contains("valid slot id"),
                    "overflow error must stay actionable, got `{fix}`"
                );
            }
            other => panic!("expected QueueFull on 65th publish, got {other:?}"),
        }
    }

    #[test]
    fn complete_io_request_only_mutates_status_word() {
        let mut buf = encode_empty_io_queue(1).unwrap();
        for (idx, byte) in buf.iter_mut().enumerate() {
            *byte = (idx % 251) as u8;
        }
        let before = buf.clone();
        complete_io_request(&mut buf, 0, false).expect("valid completion slot must update");
        let status_off = (io_word::STATUS as usize) * 4;
        for idx in 0..buf.len() {
            let in_status_word = (status_off..status_off + 4).contains(&idx);
            if !in_status_word {
                assert_eq!(
                    buf[idx], before[idx],
                    "status completion must not touch non-status byte index {idx}"
                );
            }
        }
        let status = u32::from_le_bytes(buf[status_off..status_off + 4].try_into().unwrap());
        assert_eq!(status, io_status::ERROR);
    }

    #[test]
    fn io_module_avoids_byte_width_atomic_types() {
        let src = include_str!("io.rs");
        let prod_src = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(
            !prod_src.contains("AtomicU8") && !prod_src.contains("AtomicI8"),
            "byte-width atomics are forbidden for io_queue protocol words"
        );
        assert!(
            !prod_src.contains("AtomicU16") && !prod_src.contains("AtomicI16"),
            "sub-word atomics are forbidden for io_queue protocol words"
        );
    }
}
