//! Shared byte-buffer helpers for self-substrate dispatcher calls.
//!
//! Production self-substrate paths build primitive Programs and cross the
//! backend boundary through [`crate::optimizer::dispatcher::OptimizerDispatcher`].
//! Keeping shape checks and little-endian u32 marshalling here prevents every
//! module from growing its own subtly different host-side contract.

use crate::optimizer::dispatcher::DispatchError;

/// Compute `ceil(n / d)` for dispatch-grid sizing.
#[must_use]
pub(crate) fn ceil_div_u32(n: u32, d: u32) -> u32 {
    n.div_ceil(d).max(1)
}

/// Return `n * n` as `usize`, rejecting zero and overflow with an actionable
/// dispatcher error.
pub(crate) fn checked_square_cells(n: u32, context: &str) -> Result<usize, DispatchError> {
    if n == 0 {
        return Err(DispatchError::BadInputs(format!(
            "Fix: {context} requires n > 0."
        )));
    }
    let n_us = n as usize;
    n_us.checked_mul(n_us).ok_or_else(|| {
        DispatchError::BadInputs(format!("Fix: {context} n*n overflows usize for n={n}."))
    })
}

/// Return `left * right` as `usize`, rejecting zeros and overflow with an
/// actionable dispatcher error.
pub(crate) fn checked_product_count(
    left: u32,
    right: u32,
    left_name: &str,
    right_name: &str,
    context: &str,
) -> Result<usize, DispatchError> {
    if left == 0 || right == 0 {
        return Err(DispatchError::BadInputs(format!(
            "Fix: {context} requires {left_name} > 0 and {right_name} > 0, got {left_name}={left}, {right_name}={right}."
        )));
    }
    let left_us = left as usize;
    let right_us = right as usize;
    left_us.checked_mul(right_us).ok_or_else(|| {
        DispatchError::BadInputs(format!(
            "Fix: {context} {left_name}*{right_name} overflows usize for {left_name}={left}, {right_name}={right}."
        ))
    })
}

/// Encode a u32 slice as little-endian bytes for dispatcher input buffers.
#[must_use]
pub(crate) fn u32_slice_to_le_bytes(values: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(std::mem::size_of_val(values));
    for &value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

/// Ensure a dispatcher input-vector shell has at least `count` reusable slots.
pub(crate) fn ensure_input_slots(inputs: &mut Vec<Vec<u8>>, count: usize) {
    if inputs.len() < count {
        inputs.resize_with(count, Vec::new);
    }
}

/// Fill a reusable dispatcher byte buffer with zeros without replacing the
/// allocation.
pub(crate) fn write_zero_bytes(out: &mut Vec<u8>, len: usize) {
    out.clear();
    out.resize(len, 0);
}

/// Return the exact byte count needed for `count` u32 words.
pub(crate) fn u32_word_bytes(count: usize, context: &str) -> Result<usize, DispatchError> {
    count
        .checked_mul(std::mem::size_of::<u32>())
        .ok_or_else(|| {
            DispatchError::BadInputs(format!(
                "Fix: {context} byte count overflows usize for {count} u32 word(s)."
            ))
        })
}

/// Fill a reusable dispatcher byte buffer with `count` zeroed u32 words.
pub(crate) fn write_zero_u32_words(
    out: &mut Vec<u8>,
    count: usize,
    context: &str,
) -> Result<(), DispatchError> {
    let bytes = u32_word_bytes(count, context)?;
    write_zero_bytes(out, bytes);
    Ok(())
}

/// Encode a u32 slice as little-endian bytes into caller-owned dispatcher
/// input storage.
pub(crate) fn write_u32_slice_le_bytes(out: &mut Vec<u8>, values: &[u32]) {
    out.clear();
    out.reserve(std::mem::size_of_val(values));
    for &value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// Encode a u32 slice, or a zero-filled padded buffer when the slice is empty.
pub(crate) fn write_u32_slice_or_zero_words(
    out: &mut Vec<u8>,
    values: &[u32],
    zero_words_when_empty: usize,
    context: &str,
) -> Result<(), DispatchError> {
    if values.is_empty() {
        write_zero_u32_words(out, zero_words_when_empty, context)
    } else {
        write_u32_slice_le_bytes(out, values);
        Ok(())
    }
}

/// Encode an f32 slice as little-endian bytes for dispatcher input buffers.
#[must_use]
#[cfg(test)]
pub(crate) fn f32_slice_to_le_bytes(values: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(std::mem::size_of_val(values));
    for &value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

/// Encode an f32 slice as little-endian bytes into caller-owned dispatcher
/// input storage.
pub(crate) fn write_f32_slice_le_bytes(out: &mut Vec<u8>, values: &[f32]) {
    out.clear();
    out.reserve(std::mem::size_of_val(values));
    for &value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// Decode a dispatcher u32 output buffer with exact byte-count validation.
pub(crate) fn decode_u32_output_exact(
    bytes: &[u8],
    expected_words: usize,
    context: &str,
    out: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let expected_bytes = expected_words
        .checked_mul(std::mem::size_of::<u32>())
        .ok_or_else(|| {
            DispatchError::BackendError(format!(
                "Fix: {context} output byte count overflowed usize."
            ))
        })?;
    if bytes.len() != expected_bytes {
        return Err(DispatchError::BackendError(format!(
            "Fix: {context} expected {expected_bytes} output bytes, got {}.",
            bytes.len()
        )));
    }

    out.clear();
    out.reserve(expected_words);
    for chunk in bytes.chunks_exact(std::mem::size_of::<u32>()) {
        out.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    Ok(())
}

/// Decode a dispatcher f32 output buffer with exact byte-count validation.
pub(crate) fn decode_f32_output_exact(
    bytes: &[u8],
    expected_words: usize,
    context: &str,
    out: &mut Vec<f32>,
) -> Result<(), DispatchError> {
    let expected_bytes = expected_words
        .checked_mul(std::mem::size_of::<f32>())
        .ok_or_else(|| {
            DispatchError::BackendError(format!(
                "Fix: {context} output byte count overflowed usize."
            ))
        })?;
    if bytes.len() != expected_bytes {
        return Err(DispatchError::BackendError(format!(
            "Fix: {context} expected {expected_bytes} output bytes, got {}.",
            bytes.len()
        )));
    }

    out.clear();
    out.reserve(expected_words);
    for chunk in bytes.chunks_exact(std::mem::size_of::<f32>()) {
        out.push(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u32_word_bytes_rejects_usize_overflow() {
        let overflowing_words = usize::MAX / std::mem::size_of::<u32>() + 1;
        let err = u32_word_bytes(overflowing_words, "dispatch-buffer test")
            .expect_err("overflowing u32 word count must be rejected");
        assert!(
            matches!(err, DispatchError::BadInputs(ref message) if message.contains("dispatch-buffer test")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn zero_u32_words_preserves_allocation_and_exact_byte_count() {
        let mut bytes = Vec::with_capacity(64);
        let ptr = bytes.as_ptr();
        write_zero_u32_words(&mut bytes, 3, "zero test").expect("zeroing succeeds");
        assert_eq!(bytes, vec![0; 12]);
        assert_eq!(bytes.as_ptr(), ptr);
    }

    #[test]
    fn optional_u32_slice_pads_empty_and_encodes_non_empty() {
        let mut bytes = Vec::new();
        write_u32_slice_or_zero_words(&mut bytes, &[], 2, "optional test")
            .expect("empty slice padding succeeds");
        assert_eq!(bytes, vec![0; 8]);

        write_u32_slice_or_zero_words(&mut bytes, &[0x0102_0304], 2, "optional test")
            .expect("non-empty slice encoding succeeds");
        assert_eq!(bytes, vec![4, 3, 2, 1]);
    }
}
