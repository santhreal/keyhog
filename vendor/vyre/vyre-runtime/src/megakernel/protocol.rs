//! Ring-buffer protocol constants — slot layout, control words, opcodes, debug log.
//!
//! Pure data module. No logic, no imports beyond std. Every constant
//! has a doc-comment that says what the GPU kernel does with it.

/// A single PRINTF event decoded out of the debug-log buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugRecord {
    /// Format-string id — resolved by the host against its
    /// registered format table.
    pub fmt_id: u32,
    /// Three argument words in the order the kernel wrote them.
    pub args: [u32; 3],
}

/// Megakernel host-protocol encoding and decoding error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProtocolError {
    /// A requested buffer length overflowed host address space.
    #[error("{buffer} byte length overflow. Fix: {fix}")]
    ByteLengthOverflow {
        /// Protocol buffer being sized.
        buffer: &'static str,
        /// Actionable remediation.
        fix: &'static str,
    },
    /// A byte slice is not aligned to full u32 protocol words.
    #[error("{buffer} has {byte_len} bytes, not a whole number of u32 words. Fix: {fix}")]
    MisalignedByteLength {
        /// Protocol buffer being decoded.
        buffer: &'static str,
        /// Byte length received by the decoder.
        byte_len: usize,
        /// Actionable remediation.
        fix: &'static str,
    },
    /// A requested protocol word is outside the supplied byte slice.
    #[error("{buffer} is missing word {word_idx} in {byte_len} bytes. Fix: {fix}")]
    MissingWord {
        /// Protocol buffer being decoded.
        buffer: &'static str,
        /// Word index requested.
        word_idx: usize,
        /// Byte length received by the decoder.
        byte_len: usize,
        /// Actionable remediation.
        fix: &'static str,
    },
}

/// Number of u32 words each ring-buffer slot occupies. 16 words = 64 B,
/// a cache line on x86_64 and the slot size NVMe Submission Queue
/// Entries will use when the `uring-cmd-nvme` extension lands.
pub const SLOT_WORDS: u32 = 16;

/// Word index of the slot status header (the CAS target).
pub const STATUS_WORD: u32 = 0;

/// Word index of the slot opcode (dispatched via If-tree).
pub const OPCODE_WORD: u32 = 1;

/// Word index of the slot tenant id.
pub const TENANT_WORD: u32 = 2;

/// Word index of the slot priority level.
pub const PRIORITY_WORD: u32 = 3;

/// First argument word. Opcodes read args at
/// `ring_buffer[slot_base + ARG0_WORD .. slot_base + SLOT_WORDS]`.
pub const ARG0_WORD: u32 = 4;

/// Number of u32 argument words available per slot (12).
pub const ARGS_PER_SLOT: u32 = SLOT_WORDS - ARG0_WORD;

/// Control-buffer slot layout helpers.
pub mod control;
/// Debug helpers for inspecting megakernel slot/opcode state at runtime.
pub mod debug;
/// Opcode constants and decoding utilities for megakernel slots.
pub mod opcode;
/// Slot layout helpers (per-slot offsets, ARG0 helpers).
pub mod slot;

/// Minimum control-buffer words required by the compiled megakernel ABI.
///
/// This covers shutdown, done count, tenant masks, metrics, epoch, priority
/// offsets, and the statically declared read/write buffer count in the IR.
pub const CONTROL_MIN_WORDS: u32 = 160;
/// Maximum host-observable words whose control-buffer byte length is
/// representable by the u32 wire ABI.
pub const MAX_OBSERVABLE_SLOTS: u32 = u32::MAX - control::OBSERVABLE_BASE;
/// Maximum host-observable words the allocating encoder will materialize.
pub const MAX_ENCODED_OBSERVABLE_SLOTS: u32 = 1_048_576;
/// Maximum ring slots whose byte length is representable by the u32 wire ABI.
pub const MAX_RING_SLOTS: u32 = u32::MAX / SLOT_WORDS;
/// Maximum ring slots the allocating encoder will materialize.
pub const MAX_ENCODED_RING_SLOTS: u32 = 1_048_576;
/// Maximum debug-log records whose byte length is representable by the u32 wire ABI.
pub const MAX_DEBUG_RECORDS: u32 = u32::MAX / debug::RECORD_WORDS;
/// Maximum debug-log records the allocating encoder will materialize.
pub const MAX_ENCODED_DEBUG_RECORDS: u32 = 1_048_576;

mod codec;

pub use codec::{
    control_byte_len, count_done_ring_slots, debug_log_byte_len, encode_control,
    encode_empty_debug_log, encode_empty_ring, read_debug_log, read_debug_log_into,
    read_done_count, read_epoch, read_metrics, read_metrics_into, read_observable, ring_byte_len,
    try_encode_control, try_encode_control_into, try_encode_empty_debug_log,
    try_encode_empty_debug_log_into, try_encode_empty_ring, try_encode_empty_ring_into,
    try_read_debug_log, try_read_debug_log_into, try_read_done_count, try_read_epoch,
    try_read_metrics, try_read_metrics_into, try_read_observable,
};

#[cfg(test)]
mod tests;
