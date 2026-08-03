use crate::types::*;
use keyhog_core::Chunk;
use std::borrow::Cow;

/// Maximum source bytes fed to context-driven model feature predicates.
const ML_CONTEXT_WINDOW_BYTES: usize = 8 * 1024;

/// Borrow the `[line - radius, line + radius]` window directly out of `text`.
///
/// `line` is 1-based. Returns a `&str` slice of the original buffer and remains
/// as the compatibility oracle for callers that do not own line offsets.
/// Production candidate extraction uses [`local_context_window_from_offsets`]
/// to avoid this function's prefix newline walk.
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

/// Borrow the same bounded context window as [`local_context_window`], using
/// the chunk's already-owned line-start table instead of rescanning every
/// newline before the candidate.
///
/// `line` is 1-based and `line_offsets` must come from
/// [`compute_line_offsets`] for `text`. The output is byte-identical to
/// `local_context_window`; only boundary discovery differs.
pub(crate) fn local_context_window_from_offsets<'a>(
    text: &'a str,
    line_offsets: &[usize],
    line: usize,
    radius: usize,
) -> &'a str {
    let start_line = line.saturating_sub(radius).saturating_sub(1);
    let Some(&start) = line_offsets.get(start_line) else {
        return "";
    };
    if start > text.len() {
        return "";
    }

    let window_lines = radius.saturating_mul(2).saturating_add(1);
    let end_line = start_line.saturating_add(window_lines);
    let uncapped_end = match line_offsets.get(end_line) {
        Some(&next_line_start) => next_line_start.saturating_sub(1),
        None => text.len(),
    };
    let end = uncapped_end
        .min(start.saturating_add(ML_CONTEXT_WINDOW_BYTES))
        .min(text.len());
    let end = crate::engine::floor_char_boundary(text, end);
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
    primary_start: usize,
    primary_end: usize,
    primary_value: &str,
    companion: &CompiledCompanion,
) -> Option<String> {
    const MAX_COMPANION_MATCH_BYTES: usize = 4096;

    let (window_start, window_end) = companion_search_window(
        preprocessed,
        primary_line,
        primary_start,
        primary_end,
        companion,
    )?;
    let haystack = preprocessed.text.get(window_start..window_end)?;
    let group = companion.capture_group.unwrap_or(FIRST_CAPTURE_GROUP_INDEX);

    if companion.capture_group.is_none() {
        for matched in companion.regex.find_iter(haystack) {
            if matched.len() > MAX_COMPANION_MATCH_BYTES {
                continue;
            }
            let absolute_start = window_start + matched.start();
            let absolute_end = window_start + matched.end();
            if evidence_relation_accepts(
                companion,
                primary_start,
                primary_end,
                primary_value,
                absolute_start,
                absolute_end,
                matched.as_str(),
            ) {
                return Some(matched.as_str().to_string());
            }
        }
        return None;
    }

    let mut locations = companion.regex.capture_locations();
    let mut cursor = 0usize;
    while cursor <= haystack.len() {
        let Some(whole) = companion
            .regex
            .captures_read_at(&mut locations, haystack, cursor)
        else {
            break;
        };
        cursor = crate::engine::ceil_char_boundary(
            haystack,
            if whole.end() == cursor {
                cursor + 1
            } else {
                whole.end()
            },
        );
        let Some((start, end)) = locations.get(group) else {
            continue;
        };
        if end.saturating_sub(start) > MAX_COMPANION_MATCH_BYTES {
            continue;
        }
        let Some(captured) = haystack.get(start..end) else {
            continue;
        };
        let absolute_start = window_start + start;
        let absolute_end = window_start + end;
        if evidence_relation_accepts(
            companion,
            primary_start,
            primary_end,
            primary_value,
            absolute_start,
            absolute_end,
            captured,
        ) {
            return Some(captured.to_string());
        }
    }
    None
}

fn companion_search_window(
    preprocessed: &ScannerPreprocessedText<'_>,
    primary_line: usize,
    primary_start: usize,
    primary_end: usize,
    companion: &CompiledCompanion,
) -> Option<(usize, usize)> {
    use keyhog_core::EvidenceScope;

    if primary_start > primary_end || primary_end > preprocessed.text.len() {
        return None;
    }
    let start_line = primary_line
        .saturating_sub(companion.within_lines)
        .max(FIRST_LINE_NUMBER);
    let end_line = primary_line.saturating_add(companion.within_lines);
    let line_window = line_window_offsets(preprocessed, start_line, end_line)?;
    let scope_window = match companion.scope {
        EvidenceScope::Window => line_window,
        EvidenceScope::SameLine => line_window_offsets(preprocessed, primary_line, primary_line)?,
        EvidenceScope::SameRecord => {
            record_scope_offsets(preprocessed.text.as_ref(), primary_start)?
        }
        EvidenceScope::SameObject => {
            object_scope_offsets(preprocessed.text.as_ref(), primary_start, primary_end)?
        }
    };
    let start = line_window.0.max(scope_window.0);
    let end = line_window.1.min(scope_window.1);
    (start <= primary_start && primary_end <= end && start < end).then_some((start, end))
}

fn evidence_relation_accepts(
    companion: &CompiledCompanion,
    primary_start: usize,
    primary_end: usize,
    primary_value: &str,
    evidence_start: usize,
    evidence_end: usize,
    evidence_value: &str,
) -> bool {
    use keyhog_core::{EvidenceDirection, EvidenceValueRelation};

    let direction_matches = match companion.direction {
        EvidenceDirection::Either => true,
        EvidenceDirection::Before => evidence_end <= primary_start,
        EvidenceDirection::After => evidence_start >= primary_end,
    };
    if !direction_matches {
        return false;
    }
    if let Some(max_gap) = companion.within_bytes {
        let gap = if evidence_end <= primary_start {
            primary_start - evidence_end
        } else if primary_end <= evidence_start {
            evidence_start - primary_end
        } else {
            0
        };
        if gap > max_gap {
            return false;
        }
    }
    match companion.value_relation {
        EvidenceValueRelation::Present => true,
        EvidenceValueRelation::EqualsPrimary => evidence_value == primary_value,
        EvidenceValueRelation::DiffersFromPrimary => evidence_value != primary_value,
    }
}

fn record_scope_offsets(text: &str, primary_start: usize) -> Option<(usize, usize)> {
    if primary_start > text.len() || !text.is_char_boundary(primary_start) {
        return None;
    }
    let mut start = text[..primary_start]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    while start > 0 {
        let previous_end = start - 1;
        let previous_start = text[..previous_end]
            .rfind('\n')
            .map_or(0, |newline| newline + 1);
        if text[previous_start..previous_end].trim().is_empty() {
            break;
        }
        start = previous_start;
    }

    let mut end = text[primary_start..]
        .find('\n')
        .map_or(text.len(), |newline| primary_start + newline);
    while end < text.len() {
        let next_start = end + 1;
        let next_end = text[next_start..]
            .find('\n')
            .map_or(text.len(), |newline| next_start + newline);
        if text[next_start..next_end].trim().is_empty() {
            break;
        }
        end = next_end;
    }
    Some((start, end))
}

fn object_scope_offsets(
    text: &str,
    primary_start: usize,
    primary_end: usize,
) -> Option<(usize, usize)> {
    if primary_start > primary_end || primary_end > text.len() {
        return None;
    }
    let bytes = text.as_bytes();
    let mut stack: Vec<(u8, usize)> = Vec::new();
    let mut quoted = None;
    let mut escaped = false;
    let mut smallest = None;

    for (index, byte) in bytes.iter().copied().enumerate() {
        if let Some(quote) = quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == quote {
                quoted = None;
            }
            continue;
        }
        if byte == b'"' || byte == b'\'' {
            quoted = Some(byte);
            continue;
        }
        match byte {
            b'{' | b'[' => stack.push((byte, index)),
            b'}' | b']' => {
                let expected = if byte == b'}' { b'{' } else { b'[' };
                let Some((open, start)) = stack.pop() else {
                    continue;
                };
                if open != expected {
                    stack.clear();
                    continue;
                }
                let end = index + 1;
                if start <= primary_start
                    && primary_end <= end
                    && smallest.is_none_or(|(current_start, current_end)| {
                        end - start < current_end - current_start
                    })
                {
                    smallest = Some((start, end));
                }
            }
            _ => {}
        }
    }
    smallest
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
