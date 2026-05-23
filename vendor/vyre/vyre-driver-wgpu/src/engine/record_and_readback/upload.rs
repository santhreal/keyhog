use crate::numeric::usize_to_u64;
use vyre_driver::BackendError;

pub(super) fn pool_backend_error(error: impl std::fmt::Display) -> BackendError {
    BackendError::new(format!(
        "GPU buffer pool acquisition failed: {error}. Fix: restart the process if the pool lock was poisoned, or reduce concurrent dispatch pressure."
    ))
}

pub(super) fn write_padded_input(
    queue: &wgpu::Queue,
    buffer: &wgpu::Buffer,
    bytes: &[u8],
    size: usize,
) -> Result<Option<(u64, u64)>, BackendError> {
    let aligned_len = bytes.len() & !3;
    if aligned_len > 0 {
        queue.write_buffer(buffer, 0, &bytes[..aligned_len]);
    }

    let mut zero_start = aligned_len;
    let tail_len = bytes.len() - aligned_len;
    if tail_len > 0 {
        let mut tail = [0u8; 4];
        tail[..tail_len].copy_from_slice(&bytes[aligned_len..]);
        queue.write_buffer(
            buffer,
            usize_to_u64(aligned_len, "padded input tail offset")?,
            &tail,
        );
        zero_start += 4;
    }

    if size > zero_start {
        Ok(Some((
            usize_to_u64(zero_start, "padded input zero-fill start")?,
            usize_to_u64(size - zero_start, "padded input zero-fill length")?,
        )))
    } else {
        Ok(None)
    }
}
