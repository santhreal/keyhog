//! Poll/claim helpers. Read REQUEST slots out of the queue and (in the
//! claim variant) atomically transition them to CLAIMED.

use std::sync::atomic::{fence, Ordering};

use crate::PipelineError;

use super::super::protocol::slot;
use super::helpers::{read_queue_word, validate_io_queue_view, write_queue_word, IoQueueView};
use super::{io_word, IoRequest, IO_SLOT_WORDS};

/// contains a partial IO slot, or exceeds the compiled poll window.
pub fn try_poll_io_requests(io_queue_bytes: &[u8]) -> Result<Vec<IoRequest>, PipelineError> {
    let view = validate_io_queue_view(io_queue_bytes.len())?;
    let mut requests = Vec::with_capacity(view.slot_count);
    try_poll_io_requests_into_validated(io_queue_bytes, view, &mut requests)?;
    Ok(requests)
}

/// Strictly poll pending requests into caller-owned storage without claiming.
///
/// # Errors
///
/// Returns [`PipelineError`] when the byte view is malformed or exceeds the
/// compiled poll window.
pub fn try_poll_io_requests_into(
    io_queue_bytes: &[u8],
    requests: &mut Vec<IoRequest>,
) -> Result<(), PipelineError> {
    let view = validate_io_queue_view(io_queue_bytes.len())?;
    try_poll_io_requests_into_validated(io_queue_bytes, view, requests)
}

fn try_poll_io_requests_into_validated(
    io_queue_bytes: &[u8],
    view: IoQueueView,
    requests: &mut Vec<IoRequest>,
) -> Result<(), PipelineError> {
    requests.clear();
    reserve_target_capacity(requests, view.slot_count);
    if let Ok(words) = bytemuck::try_cast_slice::<u8, u32>(io_queue_bytes) {
        poll_io_requests_words(words, view, requests);
        return Ok(());
    }
    for slot_idx in 0..view.slot_count {
        let base = slot_idx * IO_SLOT_WORDS as usize;
        let read_word = |offset: u32| -> Result<u32, PipelineError> {
            let off = (base + offset as usize) * 4;
            let bytes = io_queue_bytes.get(off..off + 4).ok_or_else(|| {
                PipelineError::Backend(format!(
                    "IO queue slot {slot_idx} word {offset} is outside the validated queue view. Fix: validate queue byte length before polling."
                ))
            })?;
            let mut word = [0u8; 4];
            word.copy_from_slice(bytes);
            fence(Ordering::Acquire);
            Ok(u32::from_le_bytes(word))
        };

        let status = read_word(io_word::STATUS)?;
        if status == slot::PUBLISHED {
            let offset_lo = read_word(io_word::OFFSET_LO)?;
            let offset_hi = read_word(io_word::OFFSET_HI)?;
            requests.push(IoRequest {
                slot_idx: slot_idx as u32,
                op_type: read_word(io_word::OP_TYPE)?,
                src_handle: read_word(io_word::SRC_HANDLE)?,
                dst_handle: read_word(io_word::DST_HANDLE)?,
                offset: ((offset_hi as u64) << 32) | (offset_lo as u64),
                byte_count: read_word(io_word::BYTE_COUNT)?,
                tag: read_word(io_word::TAG)?,
            });
        }
    }

    Ok(())
}

/// Strictly poll and claim pending requests into caller-owned storage.
///
/// Unlike [`try_poll_io_requests`], this mutates each `PUBLISHED` slot to
/// `CLAIMED` before returning it. Host IO pumps must use this entry point so a
/// still-in-flight request is not submitted again on the next poll.
///
/// # Errors
///
/// Returns [`PipelineError`] when the byte view is malformed or exceeds the
/// compiled poll window.
pub fn try_claim_io_requests_into(
    io_queue_bytes: &mut [u8],
    requests: &mut Vec<IoRequest>,
) -> Result<(), PipelineError> {
    let view = validate_io_queue_view(io_queue_bytes.len())?;
    requests.clear();
    reserve_target_capacity(requests, view.slot_count);
    if let Ok(words) = bytemuck::try_cast_slice_mut::<u8, u32>(io_queue_bytes) {
        claim_io_requests_words(words, view, requests);
        return Ok(());
    }

    for slot_idx in 0..view.slot_count {
        let base = slot_idx * IO_SLOT_WORDS as usize;
        let status = read_queue_word(io_queue_bytes, base, io_word::STATUS)?;
        if status != slot::PUBLISHED {
            continue;
        }

        write_queue_word(io_queue_bytes, base, io_word::STATUS, slot::CLAIMED)?;
        let offset_lo = read_queue_word(io_queue_bytes, base, io_word::OFFSET_LO)?;
        let offset_hi = read_queue_word(io_queue_bytes, base, io_word::OFFSET_HI)?;
        requests.push(IoRequest {
            slot_idx: slot_idx as u32,
            op_type: read_queue_word(io_queue_bytes, base, io_word::OP_TYPE)?,
            src_handle: read_queue_word(io_queue_bytes, base, io_word::SRC_HANDLE)?,
            dst_handle: read_queue_word(io_queue_bytes, base, io_word::DST_HANDLE)?,
            offset: ((offset_hi as u64) << 32) | (offset_lo as u64),
            byte_count: read_queue_word(io_queue_bytes, base, io_word::BYTE_COUNT)?,
            tag: read_queue_word(io_queue_bytes, base, io_word::TAG)?,
        });
    }

    Ok(())
}

/// Poll and claim pending requests into caller-owned storage.
///
/// # Errors
///
/// Returns [`PipelineError`] when the byte view is malformed or exceeds the
/// compiled poll window.
pub fn claim_io_requests_into(
    io_queue_bytes: &mut [u8],
    requests: &mut Vec<IoRequest>,
) -> Result<(), PipelineError> {
    try_claim_io_requests_into(io_queue_bytes, requests)
}

/// Public alias for [`try_poll_io_requests`] (legacy name kept for compatibility).
///
/// # Errors
/// See [`try_poll_io_requests`].
pub fn poll_io_requests(io_queue_bytes: &[u8]) -> Result<Vec<IoRequest>, PipelineError> {
    try_poll_io_requests(io_queue_bytes)
}
fn poll_io_requests_words(words: &[u32], view: IoQueueView, requests: &mut Vec<IoRequest>) {
    for slot_idx in 0..view.slot_count {
        let base = slot_idx * IO_SLOT_WORDS as usize;
        let status = u32::from_le(words[base + io_word::STATUS as usize]);
        if status == slot::PUBLISHED {
            fence(Ordering::Acquire);
            let offset_lo = u32::from_le(words[base + io_word::OFFSET_LO as usize]);
            let offset_hi = u32::from_le(words[base + io_word::OFFSET_HI as usize]);
            requests.push(IoRequest {
                slot_idx: slot_idx as u32,
                op_type: u32::from_le(words[base + io_word::OP_TYPE as usize]),
                src_handle: u32::from_le(words[base + io_word::SRC_HANDLE as usize]),
                dst_handle: u32::from_le(words[base + io_word::DST_HANDLE as usize]),
                offset: ((offset_hi as u64) << 32) | (offset_lo as u64),
                byte_count: u32::from_le(words[base + io_word::BYTE_COUNT as usize]),
                tag: u32::from_le(words[base + io_word::TAG as usize]),
            });
        }
    }
}

fn claim_io_requests_words(words: &mut [u32], view: IoQueueView, requests: &mut Vec<IoRequest>) {
    for slot_idx in 0..view.slot_count {
        let base = slot_idx * IO_SLOT_WORDS as usize;
        let status = u32::from_le(words[base + io_word::STATUS as usize]);
        if status != slot::PUBLISHED {
            continue;
        }
        fence(Ordering::Acquire);
        words[base + io_word::STATUS as usize] = slot::CLAIMED.to_le();
        fence(Ordering::Release);
        let offset_lo = u32::from_le(words[base + io_word::OFFSET_LO as usize]);
        let offset_hi = u32::from_le(words[base + io_word::OFFSET_HI as usize]);
        requests.push(IoRequest {
            slot_idx: slot_idx as u32,
            op_type: u32::from_le(words[base + io_word::OP_TYPE as usize]),
            src_handle: u32::from_le(words[base + io_word::SRC_HANDLE as usize]),
            dst_handle: u32::from_le(words[base + io_word::DST_HANDLE as usize]),
            offset: ((offset_hi as u64) << 32) | (offset_lo as u64),
            byte_count: u32::from_le(words[base + io_word::BYTE_COUNT as usize]),
            tag: u32::from_le(words[base + io_word::TAG as usize]),
        });
    }
}

fn reserve_target_capacity<T>(out: &mut Vec<T>, target_capacity: usize) {
    if out.capacity() < target_capacity {
        out.reserve_exact(target_capacity);
    }
}
