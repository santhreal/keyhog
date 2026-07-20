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
/// this is truncated at the cap (the leading window is still rescanned, a
/// credential in the first 16 MiB is recovered; a bomb can't OOM us).
pub(crate) const MAX_INFLATE_BYTES: u64 = 16 * 1024 * 1024;

/// True iff `bytes` begins with a gzip member magic (`1f 8b`).
#[must_use]
fn is_gzip_magic(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b
}

/// True iff `bytes` begins with a valid zlib stream header (RFC 1950).
/// CM must be 8 (deflate), CINFO must name a supported window size (`<= 7`),
/// and CMF/FLG must satisfy the FCHECK modulo-31 rule. This admits all valid
/// FLEVEL values while rejecting reserved window sizes and arbitrary text.
#[must_use]
fn is_zlib_magic(bytes: &[u8]) -> bool {
    if bytes.len() < 2 {
        return false;
    }
    let cmf = bytes[0];
    let flg = bytes[1];
    (cmf & 0x0f) == 8 && (cmf >> 4) <= 7 && (u16::from(cmf) * 256 + u16::from(flg)) % 31 == 0
}

/// Whether a decoded prefix reaches the bounded compression mechanism.
pub(crate) fn has_container_magic(bytes: &[u8]) -> bool {
    is_gzip_magic(bytes) || is_zlib_magic(bytes)
}

/// Inflate `bytes` if it is a gzip or zlib stream and the inflated output is
/// non-empty valid UTF-8; otherwise `None`. Output is bounded to
/// [`MAX_INFLATE_BYTES`].
///
/// Returns `None` (not an error) for non-container bytes, malformed streams,
/// binary (non-UTF-8) inflate output, AND streams that inflate to nothing (an
/// empty result has no credential to rescan), every path is recall-preserving:
/// the caller falls back to its normal handling of the un-inflated bytes.
#[must_use]
pub(crate) fn try_inflate_to_text(bytes: &[u8]) -> Option<String> {
    // Preallocate the compressed length: a small but non-trivial floor that skips
    // the initial `Vec` doubling reallocs for the common (small) case. Bomb-safe
    // the compressed input is tiny even when it would inflate to the cap, and
    // `read_to_end` grows from here only up to `MAX_INFLATE_BYTES`.
    let mut out = Vec::with_capacity(bytes.len());
    let inflate_result = if is_gzip_magic(bytes) {
        flate2::read::GzDecoder::new(bytes)
            .take(MAX_INFLATE_BYTES)
            .read_to_end(&mut out)
            .map(|_| "gzip")
    } else if is_zlib_magic(bytes) {
        flate2::read::ZlibDecoder::new(bytes)
            .take(MAX_INFLATE_BYTES)
            .read_to_end(&mut out)
            .map(|_| "zlib")
    } else {
        return None;
    };
    // Cap hit or mid-stream UnexpectedEof can still leave a useful prefix in
    // `out` (KH-1339). Rescan that window; original compressed bytes also stay
    // in the parent scan path.
    let container = match inflate_result {
        Ok(container) => container,
        Err(error) if !out.is_empty() => {
            crate::telemetry::record_decode_truncation();
            tracing::warn!(
                compressed_bytes = bytes.len(),
                inflated_prefix = out.len(),
                %error,
                "compressed decode truncated or failed mid-stream; rescanning inflated prefix"
            );
            "truncated"
        }
        Err(error) => {
            tracing::warn!(
                compressed_bytes = bytes.len(),
                %error,
                "compressed decode failed; original encoded bytes remain in the scan"
            );
            return None;
        }
    };
    // An empty inflate (e.g. a degenerate stored block, or the compression of an
    // empty payload) has nothing to rescan, return `None` so the caller emits no
    // empty sub-chunk, consistent with the non-container / malformed / non-UTF-8
    // `None` paths. Recall-neutral: empty text can hold no credential.
    let text = match String::from_utf8(out) {
        Ok(text) => text,
        Err(error) => {
            tracing::warn!(
                container,
                inflated_bytes = error.as_bytes().len(),
                "compressed decode produced non-UTF-8 bytes; original encoded bytes remain in the scan"
            );
            return None;
        }
    };
    if text.is_empty() {
        return None;
    }
    Some(text)
}
