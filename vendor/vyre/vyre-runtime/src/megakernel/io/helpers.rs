//! Low-level queue word access + queue-view validation + IR builders.

use crate::PipelineError;
use std::sync::atomic::{fence, Ordering};
use vyre_foundation::ir::{Expr, Node};

use super::super::protocol::slot;
use super::{io_status, io_word, IO_SLOT_COUNT, IO_SLOT_WORDS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct IoQueueView {
    pub(super) slot_count: usize,
}

pub(super) fn queue_word_index(slot_idx: u32, word: u32) -> usize {
    slot_idx as usize * IO_SLOT_WORDS as usize + word as usize
}

pub(super) fn read_queue_word(
    io_queue_bytes: &[u8],
    base_word: usize,
    word: u32,
) -> Result<u32, PipelineError> {
    let off = (base_word + word as usize) * 4;
    let bytes = io_queue_bytes.get(off..off + 4).ok_or_else(|| {
        PipelineError::Backend(format!(
            "IO queue word {word} at base {base_word} is outside the validated queue view. Fix: validate queue byte length before polling."
        ))
    })?;
    let mut word_bytes = [0u8; 4];
    fence(Ordering::Acquire);
    word_bytes.copy_from_slice(bytes);
    Ok(u32::from_le_bytes(word_bytes))
}

pub(super) fn write_queue_word(
    io_queue_bytes: &mut [u8],
    base_word: usize,
    word: u32,
    value: u32,
) -> Result<(), PipelineError> {
    write_queue_word_unfenced(io_queue_bytes, base_word, word, value)?;
    fence(Ordering::Release);
    Ok(())
}

pub(super) fn write_queue_word_unfenced(
    io_queue_bytes: &mut [u8],
    base_word: usize,
    word: u32,
    value: u32,
) -> Result<(), PipelineError> {
    let off = (base_word + word as usize) * 4;
    let bytes = io_queue_bytes.get_mut(off..off + 4).ok_or_else(|| {
        PipelineError::Backend(format!(
            "IO queue word {word} at base {base_word} is outside the validated queue view. Fix: validate queue byte length before completing."
        ))
    })?;
    bytes.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub(super) fn validate_io_queue_view(byte_len: usize) -> Result<IoQueueView, PipelineError> {
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
            // If host marked OK or ERROR, clear the slot for reuse.
            Node::if_then(
                Expr::or(
                    Expr::eq(Expr::var("io_poll_status"), Expr::u32(io_status::OK)),
                    Expr::eq(Expr::var("io_poll_status"), Expr::u32(io_status::ERROR)),
                ),
                vec![Node::store(
                    "io_queue",
                    Expr::add(Expr::var("io_poll_base"), Expr::u32(io_word::STATUS)),
                    Expr::u32(slot::EMPTY),
                )],
            ),
        ],
    )]
}
