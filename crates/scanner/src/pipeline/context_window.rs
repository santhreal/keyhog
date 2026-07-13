use crate::types::*;
use keyhog_core::Chunk;
use std::borrow::Cow;

/// Borrow the `[line - radius, line + radius]` window directly out of `text`.
///
/// `line` is 1-based. Returns a `&str` slice of the original buffer: no
/// `Vec<&str>` collect, no `join` re-allocation, and no O(file)
/// `lines().skip()` prefix walk (which iterates and discards every skipped
/// line). We locate the two byte boundaries with `memchr` newline scans -
/// O(window) for the start instead of O(file) - and slice once. Callers that
/// need ownership call `.to_string()` (still one alloc total, down from two).
pub(crate) fn local_context_window(text: &str, line: usize, radius: usize) -> &str {
    let bytes = text.as_bytes();
    // Byte offset where the first window line begins. Walk forward over the
    // `(line - radius - 1)` newlines that precede the window; if `line` is so
    // small the window starts at line 1, the start offset is simply 0.
    let lines_before = line.saturating_sub(radius).saturating_sub(1);
    let mut start = 0usize;
    for _ in 0..lines_before {
        match memchr::memchr(b'\n', &bytes[start..]) {
            // SAFETY: start is 0 initially, then set to `prev_start + pos + 1`
            // where pos is a memchr offset within &bytes[prev_start..].  After
            // the None early-return below, start <= bytes.len() always holds.
            Some(pos) => start = start + pos + 1,
            // Fewer lines than the window asks for: clamp to end of text.
            None => return "",
        }
    }
    // Hard byte cap on the window. The scan normally stops at the window's
    // line terminators, so for ordinary source (lines well under this cap) the
    // result is byte-identical to an uncapped walk. It only bites on a
    // pathological no-`\n` line of kilobytes: there, returning the whole line
    // to the per-match ML feature/keyword scan made the scan quadratic (a
    // 164 KiB single-line file with 8 K matches took tens of seconds and
    // larger ones timed out). The features only need nearby context, so a few
    // KiB is ample. Sized INDEPENDENTLY from the tighter FP-heuristic window
    // in `context::inference::surrounding_line_window` (2 KiB): that one only
    // needs a single header line, this one feeds the ML feature/keyword scan
    // and wants more neighbouring context. Same intent, different justified cap.
    const ML_CONTEXT_WINDOW_BYTES: usize = 8 * 1024;
    let cap = (start + ML_CONTEXT_WINDOW_BYTES).min(bytes.len());
    // Byte offset just past the last window line. Skip `(2*radius + 1)` line
    // terminators from `start`; the slice excludes the trailing newline so a
    // single-line window (radius 0) returns the bare line with no `\n`.
    let window_lines = radius.saturating_mul(2).saturating_add(1);
    let mut end = start;
    for n in 0..window_lines {
        if end >= cap {
            break;
        }
        match memchr::memchr(b'\n', &bytes[end..cap]) {
            // SAFETY: end starts at `start` and grows only to `cap` via memchr
            // results; cap = (start + ML_CONTEXT_WINDOW_BYTES).min(bytes.len())
            // so end <= cap <= bytes.len() at all times.
            Some(pos) => {
                // The terminator of the final window line is excluded; for
                // earlier lines it is kept so neighbours stay `\n`-joined.
                end = if n + 1 == window_lines {
                    end + pos
                } else {
                    end + pos + 1
                };
                if n + 1 == window_lines {
                    break;
                }
            }
            // No terminator before the cap: take everything up to the cap
            // (the whole remaining text if it ends first).
            None => {
                end = cap;
                break;
            }
        }
    }
    // `start` sits at a line boundary (offset 0 or just past a `\n`) and `end`
    // at a `\n` or `bytes.len()` on the normal path; only the byte-cap path can
    // land mid-codepoint, so snap `end` down through the engine boundary owner.
    let end = crate::engine::floor_char_boundary(text, end);
    // SAFETY: `start` is at a line boundary (offset 0 or just past a '\n')
    // and is therefore UTF-8-aligned. `end` was just snapped to a char boundary
    // by floor_char_boundary, which guarantees end <= text.len() and
    // is_char_boundary(end).
    &text[start..end]
}

/// Compute the byte offsets for every line in a string.
///
/// Uses `memchr` for SIMD-accelerated newline scanning (~4x faster
/// than `str::match_indices` on inputs > 1 KiB).
pub fn compute_line_offsets(text: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    // Pre-size: average line length ~40 chars is typical for source code.
    let estimated_lines = bytes.len() / 40 + 1;
    let mut offsets = Vec::with_capacity(estimated_lines);
    offsets.push(0);
    // One SIMD pass over the whole buffer: `memchr_iter` carries its search
    // state across matches, vs re-invoking `memchr` on a fresh `&bytes[start..]`
    // sub-slice per newline. `pos` is the absolute newline index, so `pos + 1`
    // is the start of the next line (identical output to the prior loop).
    for pos in memchr::memchr_iter(b'\n', bytes) {
        offsets.push(pos + 1);
    }
    offsets
}

pub(crate) fn match_line_number(
    preprocessed: &ScannerPreprocessedText<'_>,
    line_offsets: &[usize],
    offset: usize,
) -> usize {
    match preprocessed.line_for_offset(offset) {
        Some(line) => line,
        None => {
            // `line_offsets` holds the byte offset of each line start in
            // ascending order. The first offset strictly greater than
            // `offset` is its line index - which is what
            // `partition_point` returns directly. Binary search collapses
            // the prior O(L) `position()` walk into O(log L); on a 10k-
            // line file with N matches we go from N x 10k compares to
            // N x ~14.
            line_offsets.partition_point(|&lo| lo <= offset)
        }
    }
}
pub(crate) fn normalize_scannable_chunk<'a>(
    chunk: &'a Chunk,
    owned: &'a mut Option<Chunk>,
) -> &'a Chunk {
    let normalized = crate::normalize_chunk_data(&chunk.data);
    if let Cow::Owned(data) = normalized {
        *owned = Some(Chunk {
            data: data.into(),
            metadata: chunk.metadata.clone(),
        });
        owned.as_ref().unwrap_or(chunk) // LAW10: offset/owned/group absent => documented default (original chunk / first group); recall-safe
    } else {
        chunk
    }
}
pub(crate) fn find_companion(
    preprocessed: &ScannerPreprocessedText<'_>,
    primary_line: usize,
    companion: &CompiledCompanion,
) -> Option<String> {
    // Companion matches/capture-groups longer than this are skipped on both the
    // no-group `find_iter` path and the capture-group path: a multi-kilobyte
    // "match" is never a real adjacent credential, so scanning it past this cap
    // only wastes the worker. One named owner keeps the two paths in lockstep.
    const MAX_COMPANION_MATCH_BYTES: usize = 4096;
    // `primary_line` is 1-based (the return of `match_line_number` is
    // a 1-based partition_point index). Clamp the lower bound at
    // FIRST_LINE_NUMBER so a primary on line 1 with within=3 starts
    // at line 1, not line -2 (which saturates to 0 and would silently
    // shift the whole window off by one).
    let start = primary_line
        .saturating_sub(companion.within_lines)
        .max(FIRST_LINE_NUMBER);
    let end = primary_line.saturating_add(companion.within_lines);
    let (window_start, window_end) = line_window_offsets(preprocessed, start, end)?;
    // Defensive: `line_window_offsets` returns offsets relative to the
    // line index, but the underlying text may have been truncated
    // mid-scan (windowed mode, decoded chunk shorter than original)
    // so the offsets can exceed `text.len()`. Use `get` to bail out
    // cleanly instead of panicking on a `&str[..]` slice - a single
    // bogus companion lookup must never crash a worker.
    let haystack = preprocessed.text.get(window_start..window_end)?;
    let group = companion.capture_group.unwrap_or(FIRST_CAPTURE_GROUP_INDEX); // LAW10: offset/owned/group absent => documented default (original chunk / first group); recall-safe
    let line_range = start..=end;

    // Capture-group fast path: when the regex has no groups, `find_iter` is
    // strictly cheaper than `captures_iter` - `find` allocates no
    // `Captures` object per iteration. The previous unconditional
    // `captures_iter` paid for that allocation on every match across every
    // companion lookup in every scan.
    if companion.capture_group.is_none() {
        for m in companion.regex.find_iter(haystack) {
            if m.len() > MAX_COMPANION_MATCH_BYTES {
                continue;
            }
            if let Some(line) = preprocessed.line_for_offset(window_start + m.start()) {
                if line_range.contains(&line) {
                    return Some(m.as_str().to_string());
                }
            }
        }
        return None;
    }

    // Capture-group path: reuse one `CaptureLocations` buffer across every
    // iter tick. `captures_iter` allocates a fresh `Captures` per match;
    // `captures_read_at` writes into the borrowed buffer instead.
    let mut locs = companion.regex.capture_locations();
    let mut cursor = 0usize;
    let bytes_total = haystack.len();
    while cursor <= bytes_total {
        let Some(whole) = companion
            .regex
            .captures_read_at(&mut locs, haystack, cursor)
        else {
            break;
        };
        // Advance the cursor before any branch that might `continue`, to
        // keep the loop monotonic. Zero-width matches bump by one byte
        // and we then align onto a UTF-8 boundary - `captures_read_at`'s
        // behavior is unspecified at non-boundary positions, so we must
        // never feed it one.
        let next = if whole.end() == cursor {
            cursor + 1
        } else {
            whole.end()
        };
        let next = crate::engine::ceil_char_boundary(haystack, next);
        let prev_cursor = cursor;
        cursor = next;

        if let Some((s, e)) = locs.get(group) {
            if e.saturating_sub(s) <= MAX_COMPANION_MATCH_BYTES {
                if let Some(line) = preprocessed.line_for_offset(window_start + s) {
                    if line_range.contains(&line) {
                        // LAW10: use .get(s..e) instead of haystack[s..e]:
                        // the regex crate guarantees s..e are valid offsets
                        // within haystack, but a defensive get() prevents
                        // any panic from a future backend change or
                        // attacker-induced offset skew.  A None result
                        // means this capture is skipped (companion not
                        // found), recall-safe: we do not suppress the
                        // primary match, we simply miss the companion value.
                        if let Some(captured) = haystack.get(s..e) {
                            return Some(captured.to_string());
                        }
                    }
                }
            }
        }
        let _ = prev_cursor; // borrowck scope marker; cursor is already updated  // LAW10: unused-binding marker (signature/borrowck/cfg/compile-time assert); no runtime effect, not a fallback
    }
    None
}

/// Resolve the byte window `[start_offset, end_offset)` spanned by the
/// requested line range.
///
/// Contract preserved byte-for-byte from the original linear scan:
///   * `start_offset` = `start_offset` of the FIRST mapping (in vec order)
///     whose `line_number >= start_line`,
///   * `end_offset`   = `end_offset` of the LAST mapping (in vec order)
///     whose `line_number <= end_line`.
///
/// # Why a plain binary search over the whole vec is *not* correct
///
/// `mappings` is globally sorted by `start_offset` (the invariant
/// [`ScannerPreprocessedText::line_for_offset`] relies on), and its leading
/// identity prefix (one entry per original line) is additionally sorted by
/// `line_number`. But under the `multiline` feature the preprocessor APPENDS
/// structural/joined segments after that prefix whose `line_number` carries
/// the ORIGINAL source line (and, for explicit-concat / template reassembly,
/// a deliberately huge `SYNTHETIC_BASE_LINE`). So `line_number` is *not*
/// globally monotonic, a `partition_point` over the full vec would silently
/// mis-resolve the window in exactly the structural cases the synthetic line
/// numbers were chosen to keep out of the window (see
/// `crates/scanner/src/multiline/structural.rs`).
///
/// # The fix: binary-search the monotonic prefix, linear-scan only the tail
///
/// The identity prefix is `line_number`-monotonic, so the first/last lookups
/// inside it resolve with two `partition_point` searches in `O(log L)` 
/// replacing the old `O(L)` walk over every line of the file. The structural
/// tail (number of join-chains, bounded and tiny relative to `L`) is folded in
/// with a short linear pass that respects vec order: a tail hit on the START
/// side only counts when the prefix had none (prefix precedes tail), and a
/// tail hit on the END side always supersedes a prefix hit (tail follows
/// prefix). On the dominant path (passthrough / non-`multiline`) there is no
/// tail and this is a pure `O(log L)` lookup.
pub(crate) fn line_window_offsets(
    preprocessed: &ScannerPreprocessedText<'_>,
    start_line: usize,
    end_line: usize,
) -> Option<(usize, usize)> {
    let mappings = &preprocessed.mappings;

    // Length of the leading, `line_number`-monotonic identity prefix. Under
    // `multiline` the appended structural segments begin at `original_end`;
    // `mappings` is `start_offset`-sorted so the prefix is the maximal run
    // with `start_offset < original_end`, found with one binary search. In the
    // non-`multiline` build no structural segments are ever produced, so the
    // whole vec is the (line-sorted) prefix.
    let prefix_len = monotonic_prefix_len(preprocessed);
    let prefix = &mappings[..prefix_len];

    // FIRST mapping in the monotonic prefix with `line_number >= start_line`.
    let prefix_start_idx = prefix.partition_point(|m| m.line_number < start_line);
    let mut start_offset = prefix.get(prefix_start_idx).map(|m| m.start_offset);

    // LAST mapping in the monotonic prefix with `line_number <= end_line`:
    // one past it is the first with `line_number > end_line`.
    let prefix_end_idx = prefix.partition_point(|m| m.line_number <= end_line);
    let mut end_offset = (prefix_end_idx > 0).then(|| prefix[prefix_end_idx - 1].end_offset);

    // Fold in the (small) structural tail in vec order to keep the result
    // byte-identical to the original full-vec linear scan.
    for mapping in &mappings[prefix_len..] {
        // Start side: the prefix precedes the tail, so a tail entry can only
        // win the FIRST-match if the prefix produced none.
        if start_offset.is_none() && mapping.line_number >= start_line {
            start_offset = Some(mapping.start_offset);
        }
        // End side: the tail follows the prefix, so any qualifying tail entry
        // supersedes the prefix's LAST-match.
        if mapping.line_number <= end_line {
            end_offset = Some(mapping.end_offset);
        }
    }

    Some((start_offset?, end_offset?))
}

/// Length of the leading `line_number`-monotonic identity prefix of
/// `mappings` (everything before the appended structural/joined segments).
#[cfg(feature = "multiline")]
fn monotonic_prefix_len(preprocessed: &ScannerPreprocessedText<'_>) -> usize {
    // `mappings` is sorted by `start_offset`; structural segments are appended
    // at offsets `>= original_end`. Binary-search the split point.
    preprocessed
        .mappings
        .partition_point(|m| m.start_offset < preprocessed.original_end)
}

/// Non-`multiline` build: the preprocessor never appends structural segments,
/// so the entire mapping vector is the line-sorted identity prefix.
#[cfg(not(feature = "multiline"))]
fn monotonic_prefix_len(preprocessed: &ScannerPreprocessedText<'_>) -> usize {
    preprocessed.mappings.len()
}
