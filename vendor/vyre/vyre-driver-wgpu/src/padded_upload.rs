//! Shared WGPU padded upload helpers.
//!
//! WGPU buffer writes must be 4-byte aligned for the tail write paths used by
//! vyre. Centralizing the prefix/tail split keeps hot upload paths consistent
//! and prevents each caller from allocating or zero-filling differently.

use crate::numeric::usize_to_u64;
use vyre_driver::BackendError;

/// Write the aligned byte prefix and one padded 4-byte tail, returning the
/// first byte after the logical padded payload.
pub(crate) fn write_padded_prefix(
    queue: &wgpu::Queue,
    buffer: &wgpu::Buffer,
    bytes: &[u8],
    tail_offset_label: &'static str,
) -> Result<usize, BackendError> {
    let aligned_len = bytes.len() & !3;
    if aligned_len > 0 {
        queue.write_buffer(buffer, 0, &bytes[..aligned_len]);
    }

    let tail_len = bytes.len() - aligned_len;
    if tail_len == 0 {
        return Ok(aligned_len);
    }

    let mut tail = [0u8; 4];
    tail[..tail_len].copy_from_slice(&bytes[aligned_len..]);
    queue.write_buffer(buffer, usize_to_u64(aligned_len, tail_offset_label)?, &tail);
    Ok(aligned_len + 4)
}

/// Write a padded prefix and zero-fill the remaining allocation.
pub(crate) fn write_padded_and_zero_fill(
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
    let zero_start = write_padded_prefix(queue, buffer, bytes, "GPU padded tail offset")?;
    write_zero_fill(queue, buffer, zero_start, allocation_len)
}

fn write_zero_fill(
    queue: &wgpu::Queue,
    buffer: &wgpu::Buffer,
    zero_start: usize,
    allocation_len: usize,
) -> Result<(), BackendError> {
    if allocation_len <= zero_start {
        return Ok(());
    }

    static SCRATCH_ZEROS: [u8; 65_536] = [0u8; 65_536];
    let mut offset = zero_start;
    while offset < allocation_len {
        let chunk = (allocation_len - offset).min(SCRATCH_ZEROS.len());
        queue.write_buffer(
            buffer,
            usize_to_u64(offset, "GPU zero-fill offset")?,
            &SCRATCH_ZEROS[..chunk],
        );
        offset += chunk;
    }
    Ok(())
}
