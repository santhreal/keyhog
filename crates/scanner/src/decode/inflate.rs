//! Bounded gzip/zlib inflate for decode-through recall.
//!
//! A common exfil shape is `secret -> gzip -> base64`: the compressed bytes are
//! base64-encoded into otherwise-innocuous text. The base64 decoder recovers the
//! raw gzip bytes but they are not valid UTF-8, so its `from_utf8` gate drops
//! them and the credential is never rescanned. [`try_inflate_to_text`] closes
//! that gap: given decoded bytes that begin with a gzip or zlib magic, it
//! inflates them (bounded) and returns the UTF-8 text so the caller can emit a
//! rescannable sub-chunk.
//!
//! DECOMPRESSION-BOMB BOUND (Law 15): inflation is capped at
//! [`MAX_INFLATE_BYTES`] via a `Read::take` wrapper, so a maliciously small
//! blob that would expand to gigabytes stops at the cap instead of exhausting
//! memory. The cap sits well under the pipeline-wide
//! `MAX_DECODED_TOTAL_BYTES` (64 MiB) budget.

use std::io::Read;

/// Per-blob inflate output ceiling. A gzip/zlib stream that would expand past
/// this is truncated at the cap (the leading window is still rescanned — a
/// credential in the first 16 MiB is recovered; a bomb can't OOM us).
const MAX_INFLATE_BYTES: u64 = 16 * 1024 * 1024;

/// True iff `bytes` begins with a gzip member magic (`1f 8b`).
#[must_use]
pub(crate) fn is_gzip_magic(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b
}

/// True iff `bytes` begins with a zlib stream header. The second byte encodes
/// FLEVEL|FCHECK; the three common compression levels produce `78 01` (no/low),
/// `78 9c` (default), and `78 da` (best). Restricting to these avoids treating
/// arbitrary `0x78` ('x') text as a zlib stream.
#[must_use]
pub(crate) fn is_zlib_magic(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x78 && matches!(bytes[1], 0x01 | 0x9c | 0xda)
}

/// Inflate `bytes` if it is a gzip or zlib stream and the inflated output is
/// valid UTF-8; otherwise `None`. Output is bounded to [`MAX_INFLATE_BYTES`].
///
/// Returns `None` (not an error) for non-container bytes, malformed streams, and
/// binary (non-UTF-8) inflate output — every path is recall-preserving: the
/// caller falls back to its normal handling of the un-inflated bytes.
#[must_use]
pub(crate) fn try_inflate_to_text(bytes: &[u8]) -> Option<String> {
    let mut out = Vec::new();
    if is_gzip_magic(bytes) {
        flate2::read::GzDecoder::new(bytes)
            .take(MAX_INFLATE_BYTES)
            .read_to_end(&mut out)
            .ok()?;
    } else if is_zlib_magic(bytes) {
        flate2::read::ZlibDecoder::new(bytes)
            .take(MAX_INFLATE_BYTES)
            .read_to_end(&mut out)
            .ok()?;
    } else {
        return None;
    }
    String::from_utf8(out).ok()
}
