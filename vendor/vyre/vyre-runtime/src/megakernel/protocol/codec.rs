use super::{
    control, debug, slot, DebugRecord, ProtocolError, CONTROL_MIN_WORDS, MAX_DEBUG_RECORDS,
    MAX_ENCODED_DEBUG_RECORDS, MAX_ENCODED_OBSERVABLE_SLOTS, MAX_ENCODED_RING_SLOTS,
    MAX_OBSERVABLE_SLOTS, MAX_RING_SLOTS, SLOT_WORDS, STATUS_WORD,
};

/// Return the number of bytes required by a control buffer with `observable_slots`.
#[must_use]
pub fn control_byte_len(observable_slots: u32) -> Option<usize> {
    if observable_slots > MAX_OBSERVABLE_SLOTS {
        return None;
    }
    let words = control::OBSERVABLE_BASE.checked_add(observable_slots)?;
    words_to_bytes(words.max(CONTROL_MIN_WORDS))
}

/// Return the number of bytes required by a ring buffer with `slot_count` slots.
#[must_use]
pub fn ring_byte_len(slot_count: u32) -> Option<usize> {
    if slot_count > MAX_RING_SLOTS {
        return None;
    }
    let words = slot_count.checked_mul(SLOT_WORDS)?;
    words_to_bytes(words)
}

/// Return the number of bytes required by a debug-log buffer.
#[must_use]
pub fn debug_log_byte_len(record_capacity: u32) -> Option<usize> {
    if record_capacity > MAX_DEBUG_RECORDS {
        return None;
    }
    let record_words = record_capacity.checked_mul(debug::RECORD_WORDS)?;
    let words = debug::RECORDS_BASE.checked_add(record_words)?;
    words_to_bytes(words)
}

fn control_encode_capacity(observable_slots: u32) -> Result<usize, ProtocolError> {
    if observable_slots > MAX_ENCODED_OBSERVABLE_SLOTS {
        return Err(ProtocolError::ByteLengthOverflow {
            buffer: "control",
            fix: "shard observable results or reduce observable_slots to the megakernel allocation cap before encoding control",
        });
    }
    control_byte_len(observable_slots).ok_or(ProtocolError::ByteLengthOverflow {
        buffer: "control",
        fix: "shard observable results or reduce observable_slots to the megakernel protocol cap before encoding control",
    })
}

fn ring_encode_capacity(slot_count: u32) -> Result<usize, ProtocolError> {
    if slot_count > MAX_ENCODED_RING_SLOTS {
        return Err(ProtocolError::ByteLengthOverflow {
            buffer: "ring",
            fix: "split the dispatch into smaller ring shards before encoding; slot_count exceeds the megakernel allocation cap or host address space",
        });
    }
    ring_byte_len(slot_count).ok_or(ProtocolError::ByteLengthOverflow {
        buffer: "ring",
        fix: "split the dispatch into smaller ring shards before encoding; slot_count exceeds the megakernel protocol cap or host address space",
    })
}

fn debug_log_encode_capacity(record_capacity: u32) -> Result<usize, ProtocolError> {
    if record_capacity > MAX_ENCODED_DEBUG_RECORDS {
        return Err(ProtocolError::ByteLengthOverflow {
            buffer: "debug_log",
            fix:
                "reduce debug-log record_capacity to the megakernel allocation cap before encoding",
        });
    }
    debug_log_byte_len(record_capacity).ok_or(ProtocolError::ByteLengthOverflow {
        buffer: "debug_log",
        fix: "reduce debug-log record_capacity to the megakernel protocol cap before encoding",
    })
}

/// Encode a control-buffer payload.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the requested observable region overflows
/// host address space.
pub fn encode_control(
    shutdown: bool,
    tenant_count: u32,
    observable_slots: u32,
) -> Result<Vec<u8>, ProtocolError> {
    try_encode_control(shutdown, tenant_count, observable_slots)
}

/// Strictly encode a control-buffer payload.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the requested observable region overflows
/// host address space.
pub fn try_encode_control(
    shutdown: bool,
    tenant_count: u32,
    observable_slots: u32,
) -> Result<Vec<u8>, ProtocolError> {
    let mut bytes = Vec::with_capacity(control_encode_capacity(observable_slots)?);
    try_encode_control_into(shutdown, tenant_count, observable_slots, &mut bytes)?;
    Ok(bytes)
}

/// Strictly encode a control-buffer payload into caller-owned storage.
///
/// Clears and resizes `dst` to the exact control-buffer byte length, reusing
/// any existing allocation.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the requested observable region overflows
/// host address space.
pub fn try_encode_control_into(
    shutdown: bool,
    tenant_count: u32,
    observable_slots: u32,
    dst: &mut Vec<u8>,
) -> Result<(), ProtocolError> {
    let total_bytes = control_encode_capacity(observable_slots)?;
    dst.clear();
    dst.resize(total_bytes, 0);

    if shutdown {
        write_word(dst, control::SHUTDOWN as usize, 1);
    }
    write_word(dst, control::TENANT_BASE as usize, control::TENANT_BASE + 1);

    let tenant_table_start = (control::TENANT_BASE as usize) + 1;
    let requested_tenant_words = usize::try_from(tenant_count).unwrap_or(usize::MAX);
    let tenant_table_end = core::cmp::min(
        tenant_table_start.saturating_add(requested_tenant_words),
        control::TENANT_QUOTA_BASE as usize,
    );
    for word_idx in tenant_table_start..tenant_table_end {
        write_word(dst, word_idx, !0u32);
    }

    let quota_table_start = control::TENANT_QUOTA_BASE as usize;
    let quota_table_end = core::cmp::min(
        quota_table_start.saturating_add(requested_tenant_words),
        control::TENANT_FAIRNESS_BASE as usize,
    );
    for word_idx in quota_table_start..quota_table_end {
        write_word(dst, word_idx, 1_000_000);
    }
    Ok(())
}

/// Encode an empty ring buffer with `slot_count` slots.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the requested ring size overflows host
/// address space.
pub fn encode_empty_ring(slot_count: u32) -> Result<Vec<u8>, ProtocolError> {
    try_encode_empty_ring(slot_count)
}

/// Strictly encode an empty ring buffer with `slot_count` slots.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the requested ring size overflows host
/// address space.
pub fn try_encode_empty_ring(slot_count: u32) -> Result<Vec<u8>, ProtocolError> {
    let mut bytes = Vec::with_capacity(ring_encode_capacity(slot_count)?);
    try_encode_empty_ring_into(slot_count, &mut bytes)?;
    Ok(bytes)
}

/// Strictly encode an empty ring buffer into caller-owned storage.
///
/// Clears and resizes `dst` to the exact ring byte length, reusing allocation.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the requested ring size overflows host
/// address space.
pub fn try_encode_empty_ring_into(slot_count: u32, dst: &mut Vec<u8>) -> Result<(), ProtocolError> {
    let total_bytes = ring_encode_capacity(slot_count)?;
    dst.clear();
    dst.resize(total_bytes, 0);
    Ok(())
}

/// Encode an empty PRINTF channel buffer.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the requested debug-log size overflows host
/// address space.
pub fn encode_empty_debug_log(record_capacity: u32) -> Result<Vec<u8>, ProtocolError> {
    try_encode_empty_debug_log(record_capacity)
}

/// Strictly encode an empty PRINTF channel buffer.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the requested debug-log size overflows host
/// address space.
pub fn try_encode_empty_debug_log(record_capacity: u32) -> Result<Vec<u8>, ProtocolError> {
    let mut bytes = Vec::with_capacity(debug_log_encode_capacity(record_capacity)?);
    try_encode_empty_debug_log_into(record_capacity, &mut bytes)?;
    Ok(bytes)
}

/// Strictly encode an empty PRINTF channel buffer into caller-owned storage.
///
/// Clears and resizes `dst` to the exact debug-log byte length, reusing allocation.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the requested debug-log size overflows host
/// address space.
pub fn try_encode_empty_debug_log_into(
    record_capacity: u32,
    dst: &mut Vec<u8>,
) -> Result<(), ProtocolError> {
    let total_bytes = debug_log_encode_capacity(record_capacity)?;
    dst.clear();
    dst.resize(total_bytes, 0);
    Ok(())
}

/// Decode the kernel's `done_count` from a control buffer.
#[must_use]
pub fn read_done_count(control_bytes: &[u8]) -> u32 {
    read_word(control_bytes, control::DONE_COUNT as usize).unwrap_or(0)
}

/// Read the epoch counter from a control buffer.
#[must_use]
pub fn read_epoch(control_bytes: &[u8]) -> u32 {
    read_word(control_bytes, control::EPOCH as usize).unwrap_or(0)
}

/// Strictly decode the kernel's `done_count` from a control buffer.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the buffer is not word-aligned or is too
/// short to contain the fixed control header.
pub fn try_read_done_count(control_bytes: &[u8]) -> Result<u32, ProtocolError> {
    read_required_word("control", control_bytes, control::DONE_COUNT as usize)
}

/// Strictly decode the epoch counter from a control buffer.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the buffer is not word-aligned or is too
/// short to contain the epoch word.
pub fn try_read_epoch(control_bytes: &[u8]) -> Result<u32, ProtocolError> {
    read_required_word("control", control_bytes, control::EPOCH as usize)
}

/// Read an observable result word from a control buffer.
#[must_use]
pub fn read_observable(control_bytes: &[u8], index: u32) -> u32 {
    read_word(control_bytes, (control::OBSERVABLE_BASE + index) as usize).unwrap_or(0)
}

/// Strictly read an observable result word from a control buffer.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the buffer is not word-aligned, the index
/// overflows the observable word offset, or the word is outside the buffer.
pub fn try_read_observable(control_bytes: &[u8], index: u32) -> Result<u32, ProtocolError> {
    let word_idx =
        control::OBSERVABLE_BASE
            .checked_add(index)
            .ok_or(ProtocolError::ByteLengthOverflow {
                buffer: "control",
                fix: "observable index overflows the protocol word offset; shard observable reads",
            })? as usize;
    read_required_word("control", control_bytes, word_idx)
}

/// Read per-opcode metrics counters from a control buffer.
#[must_use]
pub fn read_metrics(control_bytes: &[u8]) -> Vec<(u32, u32)> {
    let mut result = Vec::with_capacity(control::METRICS_SLOTS as usize);
    read_metrics_into(control_bytes, &mut result);
    result
}

/// Read per-opcode metrics counters into caller-owned storage.
///
/// Clears `out`, then reuses its allocation.
pub fn read_metrics_into(control_bytes: &[u8], out: &mut Vec<(u32, u32)>) {
    out.clear();
    reserve_target_capacity(out, control::METRICS_SLOTS as usize);
    if let Ok(words) = bytemuck::try_cast_slice::<u8, u32>(control_bytes) {
        for i in 0..control::METRICS_SLOTS {
            let word_idx = (control::METRICS_BASE + i) as usize;
            let Some(&count) = words.get(word_idx) else {
                break;
            };
            let count = u32::from_le(count);
            if count > 0 {
                out.push((i, count));
            }
        }
        return;
    }
    for i in 0..control::METRICS_SLOTS {
        let Some(count) = read_word_unaligned(control_bytes, (control::METRICS_BASE + i) as usize)
        else {
            break;
        };
        if count > 0 {
            out.push((i, count));
        }
    }
}

/// Strictly read per-opcode metrics counters from a control buffer.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the buffer is not word-aligned or is too
/// short for the fixed metrics window.
pub fn try_read_metrics(control_bytes: &[u8]) -> Result<Vec<(u32, u32)>, ProtocolError> {
    let mut result = Vec::with_capacity(control::METRICS_SLOTS as usize);
    try_read_metrics_into(control_bytes, &mut result)?;
    Ok(result)
}

/// Strictly read per-opcode metrics counters into caller-owned storage.
///
/// Clears `out`, then reuses its allocation.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the buffer is not word-aligned or is too
/// short for the fixed metrics window.
pub fn try_read_metrics_into(
    control_bytes: &[u8],
    out: &mut Vec<(u32, u32)>,
) -> Result<(), ProtocolError> {
    validate_word_aligned("control", control_bytes)?;
    out.clear();
    reserve_target_capacity(out, control::METRICS_SLOTS as usize);
    if let Ok(words) = bytemuck::try_cast_slice::<u8, u32>(control_bytes) {
        for i in 0..control::METRICS_SLOTS {
            let word_idx = (control::METRICS_BASE + i) as usize;
            let count =
                words
                    .get(word_idx)
                    .copied()
                    .map(u32::from_le)
                    .ok_or(ProtocolError::MissingWord {
                        buffer: "control",
                        word_idx,
                        byte_len: control_bytes.len(),
                        fix: "decode only control buffers produced by the matching megakernel protocol encoder",
                    })?;
            if count > 0 {
                out.push((i, count));
            }
        }
        return Ok(());
    }
    for i in 0..control::METRICS_SLOTS {
        let word_idx = (control::METRICS_BASE + i) as usize;
        let count = read_word_unaligned(control_bytes, word_idx)
            .ok_or(ProtocolError::MissingWord {
            buffer: "control",
            word_idx,
            byte_len: control_bytes.len(),
            fix: "decode only control buffers produced by the matching megakernel protocol encoder",
        })?;
        if count > 0 {
            out.push((i, count));
        }
    }
    Ok(())
}

mod debug_log;

pub use debug_log::{
    read_debug_log, read_debug_log_into, try_read_debug_log, try_read_debug_log_into,
};

/// Count DONE slots in a ring-buffer readback.
///
/// Returns `None` when the supplied bytes cannot contain `item_count` whole
/// slots. This is intentionally part of the protocol module: DONE status is an
/// ABI word, not a backend-specific readback rule.
#[must_use]
pub fn count_done_ring_slots(ring_bytes: &[u8], item_count: usize) -> Option<u64> {
    if item_count == 0 {
        return None;
    }
    let slot_words = usize::try_from(SLOT_WORDS).ok()?;
    let required_bytes = item_count.checked_mul(slot_words)?.checked_mul(4)?;
    if ring_bytes.len() < required_bytes {
        return None;
    }
    let status_word = usize::try_from(STATUS_WORD).ok()?;
    let words = bytemuck::try_cast_slice::<u8, u32>(ring_bytes).ok();
    let done = (0..item_count)
        .filter(|slot_idx| {
            let word_idx = slot_idx
                .checked_mul(slot_words)
                .and_then(|base| base.checked_add(status_word));
            word_idx.and_then(|idx| read_word_from_optional_words(words, ring_bytes, idx))
                == Some(slot::DONE)
        })
        .count();
    Some(done as u64)
}

fn debug_log_record_capacity(debug_bytes: &[u8]) -> usize {
    let record_bytes = (debug::RECORD_WORDS as usize).saturating_mul(4);
    if record_bytes == 0 {
        0
    } else {
        debug_bytes
            .len()
            .saturating_sub((debug::RECORDS_BASE as usize).saturating_mul(4))
            / record_bytes
    }
}

fn reserve_target_capacity<T>(out: &mut Vec<T>, target_capacity: usize) {
    if out.capacity() < target_capacity {
        out.reserve_exact(target_capacity);
    }
}

fn read_word(bytes: &[u8], word_idx: usize) -> Option<u32> {
    if let Ok(words) = bytemuck::try_cast_slice::<u8, u32>(bytes) {
        return words.get(word_idx).copied().map(u32::from_le);
    }
    read_word_unaligned(bytes, word_idx)
}

fn read_word_from_optional_words(
    words: Option<&[u32]>,
    bytes: &[u8],
    word_idx: usize,
) -> Option<u32> {
    if let Some(words) = words {
        return words.get(word_idx).copied().map(u32::from_le);
    }
    read_word_unaligned(bytes, word_idx)
}

fn read_word_unaligned(bytes: &[u8], word_idx: usize) -> Option<u32> {
    let off = word_idx.checked_mul(4)?;
    let end = off.checked_add(4)?;
    let word = bytes.get(off..end)?;
    Some(u32::from_le_bytes(word.try_into().ok()?))
}

fn read_required_word(
    buffer: &'static str,
    bytes: &[u8],
    word_idx: usize,
) -> Result<u32, ProtocolError> {
    validate_word_aligned(buffer, bytes)?;
    read_word(bytes, word_idx).ok_or(ProtocolError::MissingWord {
        buffer,
        word_idx,
        byte_len: bytes.len(),
        fix: "decode only buffers produced by the matching megakernel protocol encoder",
    })
}

fn validate_word_aligned(buffer: &'static str, bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.len() % 4 == 0 {
        Ok(())
    } else {
        Err(ProtocolError::MisalignedByteLength {
            buffer,
            byte_len: bytes.len(),
            fix: "pass whole u32 protocol words; do not decode partial DMA/readback buffers",
        })
    }
}

fn write_word(bytes: &mut [u8], word_idx: usize, value: u32) {
    let off = word_idx * 4;
    bytes[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn words_to_bytes(words: u32) -> Option<usize> {
    usize::try_from(words).ok()?.checked_mul(4)
}
