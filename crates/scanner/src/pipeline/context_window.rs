use crate::types::*;
use keyhog_core::Chunk;
use std::borrow::Cow;

pub fn local_context_window(text: &str, line: usize, radius: usize) -> String {
    // Avoid collecting all lines just to slice 2*radius. Iterator-based
    // approach skips lines before the window and takes only what's needed.
    let start = line.saturating_sub(radius).saturating_sub(1);
    let end = line + radius;
    let window: Vec<&str> = text.lines().skip(start).take(end - start).collect();
    window.join("\n")
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
    let mut start = 0;
    while let Some(pos) = memchr::memchr(b'\n', &bytes[start..]) {
        offsets.push(start + pos + 1);
        start += pos + 1;
    }
    offsets
}

pub fn match_line_number(
    preprocessed: &ScannerPreprocessedText,
    line_offsets: &[usize],
    offset: usize,
) -> usize {
    preprocessed.line_for_offset(offset).unwrap_or_else(|| {
        // `line_offsets` holds the byte offset of each line start in
        // ascending order. The first offset strictly greater than
        // `offset` is its line index - which is what
        // `partition_point` returns directly. Binary search collapses
        // the prior O(L) `position()` walk into O(log L); on a 10k-
        // line file with N matches we go from N × 10k compares to
        // N × ~14.
        line_offsets.partition_point(|&lo| lo <= offset)
    })
}
pub fn normalize_scannable_chunk<'a>(chunk: &'a Chunk, owned: &'a mut Option<Chunk>) -> &'a Chunk {
    let normalized = crate::normalize_chunk_data(&chunk.data);
    if let Cow::Owned(data) = normalized {
        *owned = Some(Chunk {
            data: data.into(),
            metadata: chunk.metadata.clone(),
        });
        owned.as_ref().unwrap_or(chunk)
    } else {
        chunk
    }
}
pub fn find_companion(
    preprocessed: &ScannerPreprocessedText,
    primary_line: usize,
    companion: &CompiledCompanion,
) -> Option<String> {
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
    let group = companion.capture_group.unwrap_or(FIRST_CAPTURE_GROUP_INDEX);
    let line_range = start..=end;

    // Capture-group fast path: when the regex has no groups, `find_iter` is
    // strictly cheaper than `captures_iter` - `find` allocates no
    // `Captures` object per iteration. The previous unconditional
    // `captures_iter` paid for that allocation on every match across every
    // companion lookup in every scan.
    if companion.capture_group.is_none() {
        for m in companion.regex.find_iter(haystack) {
            if m.len() > 4096 {
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
        let mut next = if whole.end() == cursor {
            cursor + 1
        } else {
            whole.end()
        };
        while next < bytes_total && !haystack.is_char_boundary(next) {
            next += 1;
        }
        let prev_cursor = cursor;
        cursor = next;

        if let Some((s, e)) = locs.get(group) {
            if e.saturating_sub(s) <= 4096 {
                if let Some(line) = preprocessed.line_for_offset(window_start + s) {
                    if line_range.contains(&line) {
                        return Some(haystack[s..e].to_string());
                    }
                }
            }
        }
        let _ = prev_cursor; // borrowck scope marker; cursor is already updated
    }
    None
}

pub fn line_window_offsets(
    preprocessed: &ScannerPreprocessedText,
    start_line: usize,
    end_line: usize,
) -> Option<(usize, usize)> {
    let mut start_offset = None;
    let mut end_offset = None;

    for mapping in &preprocessed.mappings {
        if start_offset.is_none() && mapping.line_number >= start_line {
            start_offset = Some(mapping.start_offset);
        }
        if mapping.line_number <= end_line {
            end_offset = Some(mapping.end_offset);
        }
    }

    Some((start_offset?, end_offset?))
}
