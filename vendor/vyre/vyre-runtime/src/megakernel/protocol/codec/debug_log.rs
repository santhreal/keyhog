use super::{
    debug, debug_log_record_capacity, read_required_word, read_word_from_optional_words,
    reserve_target_capacity, validate_word_aligned,
};
use super::{DebugRecord, ProtocolError};

/// Decode PRINTF records out of the debug-log buffer.
#[must_use]
pub fn read_debug_log(debug_bytes: &[u8]) -> Vec<DebugRecord> {
    let mut records = Vec::with_capacity(debug_log_record_capacity(debug_bytes));
    read_debug_log_into(debug_bytes, &mut records);
    records
}

/// Decode PRINTF records into caller-owned storage.
///
/// Clears `out`, then reuses its allocation.
pub fn read_debug_log_into(debug_bytes: &[u8], out: &mut Vec<DebugRecord>) {
    out.clear();
    let words = bytemuck::try_cast_slice::<u8, u32>(debug_bytes).ok();
    let Some(cursor) =
        read_word_from_optional_words(words, debug_bytes, debug::CURSOR_WORD as usize)
    else {
        return;
    };
    let record_words = debug::RECORD_WORDS as usize;
    let records_start = debug::RECORDS_BASE as usize;
    let total_word_capacity = debug_bytes.len() / 4;
    let available = core::cmp::min(
        cursor as usize,
        total_word_capacity.saturating_sub(records_start),
    );
    let record_count = available / record_words;
    reserve_target_capacity(out, record_count);

    for i in 0..record_count {
        let w = records_start + i * record_words;
        out.push(DebugRecord {
            fmt_id: read_word_from_optional_words(words, debug_bytes, w).unwrap_or(0),
            args: [
                read_word_from_optional_words(words, debug_bytes, w + 1).unwrap_or(0),
                read_word_from_optional_words(words, debug_bytes, w + 2).unwrap_or(0),
                read_word_from_optional_words(words, debug_bytes, w + 3).unwrap_or(0),
            ],
        });
    }
}

/// Strictly decode PRINTF records out of the debug-log buffer.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the buffer is not word-aligned, too short for
/// the cursor word, or the cursor points at a partial record.
pub fn try_read_debug_log(debug_bytes: &[u8]) -> Result<Vec<DebugRecord>, ProtocolError> {
    let mut records = Vec::with_capacity(debug_log_record_capacity(debug_bytes));
    try_read_debug_log_into(debug_bytes, &mut records)?;
    Ok(records)
}

/// Strictly decode PRINTF records into caller-owned storage.
///
/// Clears `out`, then reuses its allocation.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the buffer is not word-aligned, too short for
/// the cursor word, or the cursor points at a partial record.
pub fn try_read_debug_log_into(
    debug_bytes: &[u8],
    out: &mut Vec<DebugRecord>,
) -> Result<(), ProtocolError> {
    validate_word_aligned("debug_log", debug_bytes)?;
    let cursor = read_required_word("debug_log", debug_bytes, debug::CURSOR_WORD as usize)?;
    let record_words = debug::RECORD_WORDS as usize;
    let records_start = debug::RECORDS_BASE as usize;
    let total_word_capacity = debug_bytes.len() / 4;
    if total_word_capacity < records_start {
        return Err(ProtocolError::MissingWord {
            buffer: "debug_log",
            word_idx: records_start,
            byte_len: debug_bytes.len(),
            fix: "build debug-log bytes with encode_empty_debug_log",
        });
    }
    let capacity_words = total_word_capacity.saturating_sub(records_start);
    if cursor as usize > capacity_words {
        return Err(ProtocolError::MissingWord {
            buffer: "debug_log",
            word_idx: records_start + cursor as usize,
            byte_len: debug_bytes.len(),
            fix: "debug-log cursor must stay within the encoded record capacity",
        });
    }
    let available = cursor as usize;
    if available % record_words != 0 {
        return Err(ProtocolError::MissingWord {
            buffer: "debug_log",
            word_idx: records_start + available,
            byte_len: debug_bytes.len(),
            fix: "debug-log cursor must advance in whole PRINTF records",
        });
    }
    let record_count = available / record_words;
    out.clear();
    reserve_target_capacity(out, record_count);
    let words = bytemuck::try_cast_slice::<u8, u32>(debug_bytes).ok();
    for i in 0..record_count {
        let w = records_start + i * record_words;
        out.push(DebugRecord {
            fmt_id: read_word_from_optional_words(words, debug_bytes, w).ok_or(
                ProtocolError::MissingWord {
                buffer: "debug_log",
                word_idx: w,
                byte_len: debug_bytes.len(),
                fix: "decode only debug-log buffers produced by the matching megakernel protocol encoder",
            })?,
            args: [
                read_word_from_optional_words(words, debug_bytes, w + 1).ok_or(
                    ProtocolError::MissingWord {
                    buffer: "debug_log",
                    word_idx: w + 1,
                    byte_len: debug_bytes.len(),
                    fix: "decode only debug-log buffers produced by the matching megakernel protocol encoder",
                })?,
                read_word_from_optional_words(words, debug_bytes, w + 2).ok_or(
                    ProtocolError::MissingWord {
                    buffer: "debug_log",
                    word_idx: w + 2,
                    byte_len: debug_bytes.len(),
                    fix: "decode only debug-log buffers produced by the matching megakernel protocol encoder",
                })?,
                read_word_from_optional_words(words, debug_bytes, w + 3).ok_or(
                    ProtocolError::MissingWord {
                    buffer: "debug_log",
                    word_idx: w + 3,
                    byte_len: debug_bytes.len(),
                    fix: "decode only debug-log buffers produced by the matching megakernel protocol encoder",
                })?,
            ],
        });
    }
    Ok(())
}
