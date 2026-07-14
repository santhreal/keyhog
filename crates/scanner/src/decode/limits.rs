//! Decode admission, per-decoder, and aggregate pipeline limits.
//!
//! Base64 and Z85 input stop at 16 MiB. Hex stops at 32 MiB because two input
//! bytes produce one decoded byte. A root retains at most 1,000 chunks and
//! 64 MiB across all decoded layers.

const MIB: usize = 1024 * 1024;

// Base64 and hex floors retain short credentials. Four Z85 groups decode to
// the minimum 16-byte candidate.
pub(super) const MIN_BASE64_CANDIDATE_LEN: usize = 12;
pub(super) const MIN_Z85_CANDIDATE_LEN: usize = 20;
pub(super) const MIN_HEX_CANDIDATE_LEN: usize = 16;

// A 24-byte base64 run can carry a roughly 16-byte secret.
#[cfg(feature = "decode")]
pub(super) const MIN_DECODABLE_RUN: usize = 24;
#[cfg(feature = "decode")]
pub(super) const MIN_PERCENT_ESCAPES: usize = 4;
#[cfg(feature = "decode")]
pub(super) const MIN_BACKSLASH_ESCAPES: usize = 2;
#[cfg(feature = "decode")]
pub(super) const MIN_HTML_NUMERIC_ENTITIES: usize = 4;

// One 16 MiB unit ties each decoder ceiling to the aggregate root budget.
const DECODE_LIMIT_UNIT_BYTES: usize = 16 * MIB;
pub(super) const MAX_BASE64_INPUT_LEN: usize = DECODE_LIMIT_UNIT_BYTES;
pub(super) const MAX_Z85_INPUT_LEN: usize = DECODE_LIMIT_UNIT_BYTES;

// Two hex input bytes produce one decoded byte, so hex gets two input units.
pub(super) const MAX_HEX_INPUT_LEN: usize = DECODE_LIMIT_UNIT_BYTES * 2;

// One root may retain four units across all decoded layers.
pub(super) const MAX_DECODED_TOTAL_BYTES: usize = DECODE_LIMIT_UNIT_BYTES * 4;
pub(super) const MAX_DECODED_CHUNKS_PER_ROOT: usize = 1000;
