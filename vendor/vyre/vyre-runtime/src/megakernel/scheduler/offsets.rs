use super::{priority, PRIORITY_LEVELS, PRIORITY_OFFSETS_BASE};
use crate::PipelineError;

/// Encode default priority partition offsets for uniform distribution.
///
/// Each priority level gets `total_slots / PRIORITY_LEVELS` slots.
/// Any remainder goes to the NORMAL partition.
#[must_use]
pub fn default_priority_offsets(total_slots: u32) -> Vec<u32> {
    let mut offsets = Vec::with_capacity(PRIORITY_LEVELS as usize + 1);
    for value in default_priority_offsets_array(total_slots) {
        offsets.push(value);
    }
    offsets
}

/// Encode default priority partition offsets into a fixed array.
///
/// Hot callers that immediately write offsets into a control buffer can use
/// this path to avoid allocating the compatibility `Vec` returned by
/// [`default_priority_offsets`].
#[must_use]
pub fn default_priority_offsets_array(total_slots: u32) -> [u32; PRIORITY_LEVELS as usize + 1] {
    let mut offsets = [0u32; PRIORITY_LEVELS as usize + 1];
    write_default_priority_offsets_array(total_slots, &mut offsets);
    offsets
}

fn write_default_priority_offsets_array(total_slots: u32, offsets: &mut [u32; 6]) {
    let base_per_pri = total_slots / PRIORITY_LEVELS;
    let remainder = total_slots % PRIORITY_LEVELS;
    let mut cursor = 0u32;
    for pri in 0..PRIORITY_LEVELS {
        offsets[pri as usize] = cursor;
        let size = base_per_pri
            + if pri == priority::NORMAL {
                remainder
            } else {
                0
            };
        cursor += size;
    }
    offsets[PRIORITY_LEVELS as usize] = cursor;
}

/// Write default priority partition offsets into an encoded control buffer.
///
/// # Errors
///
/// Returns [`PipelineError::QueueFull`] when the provided control buffer is too
/// short or not aligned to u32 words.
pub fn write_default_priority_offsets(
    control_bytes: &mut [u8],
    total_slots: u32,
) -> Result<(), PipelineError> {
    if control_bytes.len() % 4 != 0 {
        return Err(PipelineError::QueueFull {
            queue: "submission",
            fix: "control buffer byte length is not 4-byte aligned; rebuild it with Megakernel::encode_control",
        });
    }
    let mut offsets = [0u32; PRIORITY_LEVELS as usize + 1];
    write_default_priority_offsets_array(total_slots, &mut offsets);
    for (i, value) in offsets.iter().enumerate() {
        let word_idx = PRIORITY_OFFSETS_BASE as usize + i;
        let start = word_idx.checked_mul(4).ok_or(PipelineError::QueueFull {
            queue: "submission",
            fix: "priority-offset byte index overflowed usize; keep control ABI constants bounded",
        })?;
        let end = start.checked_add(4).ok_or(PipelineError::QueueFull {
            queue: "submission",
            fix: "priority-offset byte index overflowed usize; keep control ABI constants bounded",
        })?;
        let dst = control_bytes.get_mut(start..end).ok_or(PipelineError::QueueFull {
            queue: "submission",
            fix: "control buffer is too small for priority partition offsets; rebuild it with Megakernel::encode_control",
        })?;
        dst.copy_from_slice(&value.to_le_bytes());
    }
    Ok(())
}
