//! Shared GPU dispatch primitives for matching engines.
//!
//! Every high-level matcher in `vyre-libs::matching` (`GpuLiteralSet`,
//! `RulePipeline`, future ones) needs the same four operations to talk
//! to a `VyreBackend`:
//!
//!   1. Pack a haystack `&[u8]` into `u32` words for the read-only
//!      input storage buffer.
//!   2. Encode an arbitrary `&[u32]` slice as little-endian bytes for
//!      a storage buffer.
//!   3. Validate the haystack's length fits in `u32` (the wire-format
//!      bound that vyre's IR enforces) and return a typed
//!      `BackendError` with an actionable `Fix:` message otherwise.
//!   4. Compute the per-axis grid geometry that maps haystack bytes
//!      onto the program's `workgroup_size[0]` lane fan-out.
//!
//! Each of those was duplicated 2x as I added the second matcher
//! (`RulePipeline::scan`). Centralising them here makes the *next*
//! matcher (parser combinators, taint-flow scan, custom regex
//! compositions in `downstream analyzer`) free to compose — write the unique
//! plumbing, reuse the shared four.
//!
//! The output-unpacking step is intentionally **not** centralised:
//! `GpuLiteralSet` uses a two-buffer layout (`match_count` + `matches`),
//! while `RulePipeline` uses a single hit buffer with embedded counter.
//! Forcing them into one helper would push a layout choice into the
//! shared lib that consumers can't override; keeping the unpack at
//! the call site is the lego-block-correct boundary.

use std::borrow::Cow;

use vyre::{BackendError, DispatchConfig};

/// Pack a haystack of bytes into `u32` little-endian words ready for an
/// input storage buffer. Each 4 input bytes become one little-endian
/// `u32`; a tail less than 4 bytes is zero-padded into the high lanes.
///
/// This is the layout every vyre matcher's `BufferDecl::storage(..,
/// DataType::U32, ReadOnly)` haystack input expects.
#[must_use]
pub fn pack_haystack_u32(haystack: &[u8]) -> Vec<u8> {
    let padded_len = haystack.len().div_ceil(4) * 4;
    let mut packed = Vec::with_capacity(padded_len);
    packed.extend_from_slice(haystack);
    packed.resize(padded_len, 0);
    packed
}

/// Pack a `&[u32]` into a little-endian `Vec<u8>` suitable for upload
/// to a storage buffer of type `DataType::U32`.
#[must_use]
pub fn pack_u32_slice(words: &[u32]) -> Vec<u8> {
    if cfg!(target_endian = "little") {
        return bytemuck::cast_slice(words).to_vec();
    }
    let mut out = Vec::with_capacity(words.len() * 4);
    for &w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

/// Borrow a `u32` slice as little-endian bytes on little-endian hosts,
/// falling back to an owned conversion on big-endian targets.
#[must_use]
pub fn u32_words_as_le_bytes(words: &[u32]) -> Cow<'_, [u8]> {
    if cfg!(target_endian = "little") {
        Cow::Borrowed(bytemuck::cast_slice(words))
    } else {
        Cow::Owned(pack_u32_slice(words))
    }
}

/// Validate that `haystack.len()` fits in a `u32` and return it. Vyre's
/// IR uses `u32` for buffer indices, and most matching kernels rely on
/// it indirectly via 4 GiB-bounded loop counters; the check belongs at
/// the dispatch boundary so the user-facing error message points at the
/// real fix (split the input).
///
/// # Errors
/// Returns a `BackendError` carrying the message
/// `"<context> haystack length exceeds u32 capacity. Fix: split the
/// scan into chunks smaller than 4 GiB."` so callers can include their
/// engine name in the surfaced diagnostic.
pub fn haystack_len_u32(haystack: &[u8], context: &str) -> Result<u32, BackendError> {
    u32::try_from(haystack.len()).map_err(|_| {
        BackendError::new(format!(
            "{context} haystack length exceeds u32 capacity. \
             Fix: split the scan into chunks smaller than 4 GiB."
        ))
    })
}

/// Default scan-guard ceiling. Picked at 1 GiB on the assumption that
/// a single GPU dispatch over more than 1 GiB of haystack is almost
/// always a caller bug — fragmenting at this granularity keeps device
/// allocations bounded and lets failed segments retry independently.
/// Callers that genuinely need the full u32 range pass `u32::MAX` to
/// [`scan_guard`].
pub const DEFAULT_MAX_SCAN_BYTES: u32 = 1 << 30;

/// Pre-dispatch length check: enforce both the hard `u32` cap (the IR
/// limit) **and** a configurable `max_bytes` ceiling (the
/// caller-policy limit) in one call. Returns the validated length so
/// callers don't need a separate `u32::try_from` site.
///
/// This is the single source of truth for "how big a haystack will
/// vyre accept on this dispatch?" — every matcher in `vyre-libs` is
/// expected to call it before assembling input buffers, so the
/// surface message on overflow is uniform across engines.
///
/// # Errors
/// Returns a [`BackendError`] when:
/// - `haystack.len()` exceeds `u32::MAX` (carries the
///   `haystack_len_u32` overflow message).
/// - `haystack.len()` exceeds `max_bytes` (carries a
///   `Fix: split the scan…` message that names the limit).
pub fn scan_guard(haystack: &[u8], context: &str, max_bytes: u32) -> Result<u32, BackendError> {
    let len = haystack_len_u32(haystack, context)?;
    if len > max_bytes {
        return Err(BackendError::new(format!(
            "{context} haystack length {len} bytes exceeds scan-guard ceiling {max_bytes} bytes. \
             Fix: split the scan into chunks <= {max_bytes} bytes, or pass a larger \
             max_bytes if the larger dispatch is intentional."
        )));
    }
    Ok(len)
}

/// Compute the standard "one workgroup per `workgroup_size[0]` haystack
/// bytes" grid geometry. Every byte-scan matcher in `vyre-libs::matching`
/// uses the same X-axis lane fan-out, so callers should not duplicate
/// this divceil-clamp arithmetic at every dispatch site.
#[must_use]
pub fn byte_scan_dispatch_config(haystack_len: u32, workgroup_x: u32) -> DispatchConfig {
    let mut config = DispatchConfig::default();
    let workgroups = haystack_len.div_ceil(workgroup_x.max(1)).max(1);
    config.grid_override = Some([workgroups, 1, 1]);
    config
}

/// Compute grid geometry for matchers that assign one workgroup to
/// each candidate start offset. Subgroup-local lanes cooperate inside
/// that workgroup to advance the automaton state, so X-grid density is
/// the input byte count rather than `haystack_len / workgroup_size`.
#[must_use]
pub fn candidate_start_dispatch_config(haystack_len: u32) -> DispatchConfig {
    let mut config = DispatchConfig::default();
    config.grid_override = Some([haystack_len.max(1), 1, 1]);
    config
}

/// Decode a packed match-triple buffer (`pid, start, end` × N) into
/// [`vyre_foundation::match_result::Match`] values. The triple layout is
/// shared between `GpuLiteralSet` and `RulePipeline`; only the *position*
/// of the buffer in the dispatch outputs differs.
///
/// Decodes at most `count` triples and never reads past a complete 12-byte
/// record, so the returned length is
/// `min(count, triples_bytes.len() / 12)`. Extra bytes after the last full
/// triple are ignored. Using a `usize` lane index keeps `i * 12` inside
/// buffer-derived bounds and avoids `(i as usize) * 12` wrapping on 32-bit
/// targets when `count` is large but the buffer is short.
#[must_use]
pub fn unpack_match_triples(
    triples_bytes: &[u8],
    count: u32,
) -> Vec<vyre_foundation::match_result::Match> {
    let n = decoded_match_triple_count(triples_bytes, count);
    let mut results = Vec::with_capacity(n);
    unpack_match_triples_into(triples_bytes, count, &mut results);
    results
}

/// Caller-owned variant of [`unpack_match_triples`].
///
/// Reuses `results` across dispatches and therefore removes one hot
/// allocation from benchmark loops and long-running daemons. The decode
/// contract is identical to [`unpack_match_triples`]: at most `count`
/// complete triples are read, truncated tail bytes are ignored, and the
/// final output is sorted by [`vyre_foundation::match_result::Match`]'s
/// ordering.
pub fn unpack_match_triples_into(
    triples_bytes: &[u8],
    count: u32,
    results: &mut Vec<vyre_foundation::match_result::Match>,
) {
    results.clear();
    let n = decoded_match_triple_count(triples_bytes, count);
    results.reserve(n);
    for i in 0..n {
        let off = i * 12;
        let pid = u32::from_le_bytes([
            triples_bytes[off],
            triples_bytes[off + 1],
            triples_bytes[off + 2],
            triples_bytes[off + 3],
        ]);
        let start = u32::from_le_bytes([
            triples_bytes[off + 4],
            triples_bytes[off + 5],
            triples_bytes[off + 6],
            triples_bytes[off + 7],
        ]);
        let end = u32::from_le_bytes([
            triples_bytes[off + 8],
            triples_bytes[off + 9],
            triples_bytes[off + 10],
            triples_bytes[off + 11],
        ]);
        results.push(vyre_foundation::match_result::Match::new(pid, start, end));
    }
    results.sort_unstable();
}

#[inline]
fn decoded_match_triple_count(triples_bytes: &[u8], count: u32) -> usize {
    let max_complete = triples_bytes.len() / 12;
    (count as usize).min(max_complete)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_haystack_aligned() {
        let bytes = b"abcdefgh";
        let packed = pack_haystack_u32(bytes);
        // Two LE u32 words: "abcd" → 0x64636261, "efgh" → 0x68676665.
        assert_eq!(packed, vec![0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68]);
    }

    #[test]
    fn pack_haystack_unaligned_zero_pads() {
        let bytes = b"abc";
        let packed = pack_haystack_u32(bytes);
        // Single u32: "abc\0" → 0x00636261. Tail high lane is 0.
        assert_eq!(packed, vec![0x61, 0x62, 0x63, 0x00]);
    }

    #[test]
    fn pack_haystack_empty() {
        assert!(pack_haystack_u32(&[]).is_empty());
    }

    #[test]
    fn pack_u32_slice_layout() {
        let words: [u32; 2] = [0x01020304, 0xAABBCCDD];
        assert_eq!(
            pack_u32_slice(&words),
            vec![0x04, 0x03, 0x02, 0x01, 0xDD, 0xCC, 0xBB, 0xAA]
        );
    }

    #[test]
    fn u32_words_as_le_bytes_matches_pack_layout() {
        let words: [u32; 2] = [0x01020304, 0xAABBCCDD];
        let bytes = u32_words_as_le_bytes(&words);
        assert_eq!(
            bytes.as_ref(),
            [0x04, 0x03, 0x02, 0x01, 0xDD, 0xCC, 0xBB, 0xAA]
        );
        if cfg!(target_endian = "little") {
            assert!(matches!(bytes, std::borrow::Cow::Borrowed(_)));
        }
    }

    #[test]
    fn haystack_len_under_4gib_ok() {
        let buf = vec![0u8; 1024];
        assert_eq!(haystack_len_u32(&buf, "test").unwrap(), 1024);
    }

    #[test]
    fn scan_guard_under_ceiling_ok() {
        let buf = vec![0u8; 1024];
        assert_eq!(
            scan_guard(&buf, "test", DEFAULT_MAX_SCAN_BYTES).unwrap(),
            1024
        );
    }

    #[test]
    fn scan_guard_over_ceiling_errors() {
        let buf = vec![0u8; 1024];
        let err = scan_guard(&buf, "test", 512).expect_err("over ceiling must err");
        let msg = format!("{err}");
        assert!(
            msg.contains("scan-guard ceiling"),
            "scan_guard error must name the ceiling, got: {msg}"
        );
        assert!(
            msg.contains("512"),
            "must echo the ceiling number, got: {msg}"
        );
    }

    #[test]
    fn scan_guard_zero_ceiling_rejects_nonempty() {
        let buf = vec![0u8; 1];
        assert!(scan_guard(&buf, "ctx", 0).is_err());
    }

    #[test]
    fn scan_guard_zero_ceiling_accepts_empty() {
        let buf: Vec<u8> = vec![];
        assert_eq!(scan_guard(&buf, "ctx", 0).unwrap(), 0);
    }

    #[test]
    fn scan_guard_at_max_u32_ceiling_accepts_real_inputs() {
        let buf = vec![0u8; 1 << 16];
        assert_eq!(scan_guard(&buf, "ctx", u32::MAX).unwrap(), 1 << 16);
    }

    #[test]
    fn dispatch_config_clamps_at_one() {
        // Haystack shorter than a single workgroup must still yield ≥1
        // workgroup so the kernel actually runs.
        let cfg = byte_scan_dispatch_config(0, 64);
        assert_eq!(cfg.grid_override, Some([1, 1, 1]));
    }

    #[test]
    fn dispatch_config_divceils() {
        let cfg = byte_scan_dispatch_config(129, 64);
        assert_eq!(cfg.grid_override, Some([3, 1, 1]));
    }

    #[test]
    fn unpack_match_triples_sorts() {
        let bytes = [
            // (pid=2, start=10, end=20)
            2, 0, 0, 0, 10, 0, 0, 0, 20, 0, 0, 0, // (pid=1, start=5, end=8)
            1, 0, 0, 0, 5, 0, 0, 0, 8, 0, 0, 0,
        ];
        let matches = unpack_match_triples(&bytes, 2);
        assert_eq!(matches.len(), 2);
        // sort_unstable orders by (start, end, pid) via Match's Ord impl.
        assert!(matches[0].start <= matches[1].start);
    }

    #[test]
    fn unpack_match_triples_into_reuses_caller_buffer() {
        let bytes = [
            2, 0, 0, 0, 10, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 8, 0, 0, 0,
        ];
        let mut matches = Vec::with_capacity(8);
        let ptr = matches.as_ptr();

        unpack_match_triples_into(&bytes, 2, &mut matches);

        assert_eq!(matches.len(), 2);
        assert_eq!(matches.as_ptr(), ptr);
        assert!(matches[0].start <= matches[1].start);
    }

    /// Adversarial / regression: a bogus or truncated readback may pair a
    /// huge `count` (e.g. `u32::MAX`) with a short buffer. The decoder must
    /// only walk full 12-byte triples so we never form `off` from a wrapped
    /// `u32_index * 12` on 32-bit `usize` before comparing to `len`, and we
    /// return exactly the complete records present (not a silent under-filled
    /// long vec).
    #[test]
    fn unpack_match_triples_huge_count_short_buffer_stays_in_bounds() {
        let bytes = [
            7u8, 0, 0, 0, // pid
            1, 0, 0, 0, // start
            3, 0, 0, 0, // end
        ];
        let matches = unpack_match_triples(&bytes, u32::MAX);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_id, 7);
        assert_eq!(matches[0].start, 1);
        assert_eq!(matches[0].end, 3);
    }
}
