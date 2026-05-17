//! Completion-write helpers. Update the queue with the result of a
//! serviced IO operation so the GPU sees COMPLETE for that slot.

use std::sync::atomic::{fence, Ordering};

use crate::PipelineError;

use super::super::protocol::slot;
use super::helpers::{
    read_queue_word, validate_io_queue_view, write_queue_word_unfenced, IoQueueView,
};
use super::{io_status, io_word, IO_SLOT_WORDS};

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
    try_complete_io_requests_batch(io_queue_bytes, &[(slot_idx, success)])
}

/// Strictly complete several claimed IO requests after one validation pass.
///
/// # Errors
///
/// Returns [`PipelineError`] without mutating the queue when any completion
/// references an invalid slot or a slot not currently owned as `CLAIMED`.
pub fn try_complete_io_requests_batch(
    io_queue_bytes: &mut [u8],
    completions: &[(u32, bool)],
) -> Result<(), PipelineError> {
    let view = validate_io_queue_view(io_queue_bytes.len())?;
    if let Ok(words) = bytemuck::try_cast_slice_mut::<u8, u32>(io_queue_bytes) {
        return complete_io_requests_words(words, view, completions);
    }
    for (slot_idx, _) in completions {
        if *slot_idx as usize >= view.slot_count {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "io_queue completion slot exceeds queue length; complete a valid slot id",
            });
        }
        let base_word = (*slot_idx as usize) * (IO_SLOT_WORDS as usize);
        let current_status = read_queue_word(io_queue_bytes, base_word, io_word::STATUS)?;
        if current_status != slot::CLAIMED {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "io_queue completion requires a CLAIMED request; poll with claim_io_requests_into before completing so the same DMA is not completed without ownership",
            });
        }
    }
    for (slot_idx, success) in completions {
        let base_word = (*slot_idx as usize) * (IO_SLOT_WORDS as usize);
        let status = if *success {
            io_status::OK
        } else {
            io_status::ERROR
        };
        write_queue_word_unfenced(io_queue_bytes, base_word, io_word::STATUS, status)?;
    }
    fence(Ordering::Release);
    Ok(())
}

fn complete_io_requests_words(
    words: &mut [u32],
    view: IoQueueView,
    completions: &[(u32, bool)],
) -> Result<(), PipelineError> {
    for (slot_idx, _) in completions {
        if *slot_idx as usize >= view.slot_count {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "io_queue completion slot exceeds queue length; complete a valid slot id",
            });
        }
        let base = (*slot_idx as usize) * (IO_SLOT_WORDS as usize);
        fence(Ordering::Acquire);
        let current_status = u32::from_le(words[base + io_word::STATUS as usize]);
        if current_status != slot::CLAIMED {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "io_queue completion requires a CLAIMED request; poll with claim_io_requests_into before completing so the same DMA is not completed without ownership",
            });
        }
    }
    for (slot_idx, success) in completions {
        let base = (*slot_idx as usize) * (IO_SLOT_WORDS as usize);
        let status = if *success {
            io_status::OK
        } else {
            io_status::ERROR
        };
        words[base + io_word::STATUS as usize] = status.to_le();
    }
    fence(Ordering::Release);
    Ok(())
}

/// Complete several serviced IO requests.
///
/// # Errors
///
/// See [`try_complete_io_requests_batch`].
pub fn complete_io_requests_batch(
    io_queue_bytes: &mut [u8],
    completions: &[(u32, bool)],
) -> Result<(), PipelineError> {
    try_complete_io_requests_batch(io_queue_bytes, completions)
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
