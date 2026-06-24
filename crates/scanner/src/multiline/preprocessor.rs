use super::config::{
    should_passthrough, source_line_offset_or_record_gap, LineMapping, MultilineConfig,
    PreprocessedText,
};
use super::string_extract::{extract_string_part, ContinuationType};
use super::structural::collect_structural_fragments;
use crate::fragment_cache::FragmentCache;

/// Join adjacent string fragments and continuations before scanning.
///
/// The returned [`PreprocessedText`] borrows `text` (`Cow::Borrowed`) on the
/// passthrough / no-concatenation paths — the byte-identical common case — and
/// only owns a fresh `String` (`Cow::Owned`) when a real concatenation join or
/// structural fragment actually appends NEW bytes.
pub(crate) fn preprocess_multiline<'a>(
    text: impl Into<std::borrow::Cow<'a, str>>,
    config: &MultilineConfig,
    fragment_cache: &FragmentCache,
) -> PreprocessedText<'a> {
    // Accept anything convertible into `Cow<'a, str>` (`&str`, `String`,
    // `Cow`) so existing `&str` callers keep working while the scan hot path
    // hands in the chunk's already-borrowed `Cow` so a passthrough chunk is
    // never copied.
    let text_owned: std::borrow::Cow<'a, str> = text.into();
    // `text_owned` is the owning Cow (borrowed for a passthrough chunk, owned
    // when normalization rewrote it). It is consumed ONLY at the byte-identical
    // return points so a borrowed chunk passes through with no full-body copy;
    // every read-only analysis below goes through the `&str` view `text`.
    let text: &str = &text_owned;

    if should_passthrough(text) {
        return passthrough_text(text_owned);
    }

    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return PreprocessedText {
            text: std::borrow::Cow::Borrowed(""),
            original_end: 0,
            mappings: Vec::new(),
        };
    }

    let first_nonwhite = text.trim_start().chars().next().unwrap_or(' '); // LAW10: empty/absent => documented numeric/sentinel default, recall-safe
    if first_nonwhite == '{' || first_nonwhite == '[' {
        return passthrough_text(text_owned);
    }

    let mut result_lines = Vec::new();
    let mut mappings = Vec::new();
    let source_line_offsets = crate::compute_line_offsets(text);
    let mut current_offset = 0usize;
    let mut index = 0;
    while index < lines.len() {
        let (joined_line, lines_consumed, line_mappings) =
            process_line_chain(&lines, &source_line_offsets, index, config, current_offset);

        if !joined_line.is_empty() {
            let total_len = joined_line.len();
            mappings.extend(line_mappings);
            current_offset += total_len + 1;
        }

        result_lines.push(joined_line);
        index += lines_consumed.max(1);
    }

    let joined_text = result_lines.join("\n");
    let original_end = text.len();

    let joined_trimmed = joined_text.trim();
    let text_trimmed = text.trim();
    let is_real_concatenation = joined_trimmed != text_trimmed;
    let will_append = is_real_concatenation && !joined_text.is_empty();

    // Structural fragments are appended after any concatenation join, so their
    // offsets start past the (possibly extended) text. Computing that base
    // arithmetically (rather than from `final_text.len()`) lets us probe for
    // structural fragments before materializing the extended buffer, so the
    // no-fragment case below can return without ever building it.
    //
    // When `will_append` is true the buffer is `text` + '\n' + `joined_text`
    // and the structural region is push_str'd DIRECTLY onto it (the
    // `if !appended_any { push('\n') }` separator below is skipped because the
    // join already pushed one), so the structural content starts at
    // `original_end + 1 + joined_text.len()` with no extra separator byte. The
    // `else` branch DOES emit a leading '\n' before the structural region, so
    // its base is `original_end + 1`.
    let structural_base = if will_append {
        original_end + 1 + joined_text.len()
    } else {
        original_end + 1
    };
    let (structural_joined, structural_mappings) = collect_structural_fragments(
        &lines,
        &source_line_offsets,
        structural_base,
        fragment_cache,
    );

    // Delay the full-chunk `text.to_string()` copy until we know there is
    // actually something to append. When neither a real concatenation join nor
    // a structural fragment was found (the common case for a chunk that merely
    // tripped a concatenation indicator), `final_text` would equal the input
    // verbatim, so we skip pushing `joined_text`/structural segments into a new
    // buffer. The chain `mappings` are still emitted unshifted (matching the
    // original path, which only shifts them when the join is appended) so the
    // offset→line map is byte-identical to the eager-copy result.
    if !will_append && structural_joined.is_empty() {
        // Byte-identical to the input (no join, no structural fragment): carry
        // the original Cow through unchanged instead of copying the body into a
        // fresh String. A borrowed chunk stays borrowed; a normalization-owned
        // buffer is moved, not re-copied.
        let mut original_mappings = identity_line_mappings(text, original_end);
        original_mappings.extend(mappings);
        return PreprocessedText {
            text: text_owned,
            original_end,
            mappings: original_mappings,
        };
    }

    let mut final_text = text.to_string();
    let mut appended_any = false;

    if will_append {
        final_text.push('\n');
        final_text.push_str(&joined_text);

        let append_start = original_end + 1;
        for mapping in &mut mappings {
            mapping.start_offset += append_start;
            mapping.end_offset += append_start;
        }
        appended_any = true;
    }

    if !structural_joined.is_empty() {
        if !appended_any {
            final_text.push('\n');
        }
        final_text.push_str(&structural_joined.join("\n"));
        mappings.extend(structural_mappings);
    }

    let mut original_mappings = identity_line_mappings(text, original_end);
    original_mappings.extend(mappings);

    PreprocessedText {
        // `final_text` is the input plus appended join/structural bytes — newly
        // synthesized, so it is owned.
        text: std::borrow::Cow::Owned(final_text),
        original_end,
        mappings: original_mappings,
    }
}

/// Build the identity offset→line map over the original `text` (one entry per
/// `'\n'`-separated segment, `end_offset` clamped to `original_end`). This is
/// the mapping prefix shared by both the passthrough early-return and the
/// concatenation path, so it lives in one place rather than being inlined
/// twice.
fn identity_line_mappings(text: &str, original_end: usize) -> Vec<LineMapping> {
    let mut original_mappings = Vec::new();
    let mut offset = 0;
    for (line_idx, line) in text.split('\n').enumerate() {
        let end = offset + line.len();
        original_mappings.push(LineMapping {
            line_number: line_idx + 1,
            start_offset: offset,
            end_offset: (end + 1).min(original_end),
            original_start_offset: offset,
        });
        offset = end + 1;
    }
    original_mappings
}

fn passthrough_text(text: std::borrow::Cow<'_, str>) -> PreprocessedText<'_> {
    let original_end = text.len();
    let mappings = if text.is_empty() {
        Vec::new()
    } else {
        identity_line_mappings(&text, original_end)
    };
    PreprocessedText {
        // Byte-identical passthrough: carry the Cow through with no body copy.
        text,
        original_end,
        mappings,
    }
}

fn process_line_chain(
    lines: &[&str],
    source_line_offsets: &[usize],
    start_idx: usize,
    config: &MultilineConfig,
    base_offset: usize,
) -> (String, usize, Vec<LineMapping>) {
    let mut joined_parts = Vec::new();
    let mut current_idx = start_idx;
    let mut lines_consumed = 0usize;
    let original_start_line = start_idx + 1;

    let join_limit = config.max_join_lines.max(1);
    while current_idx < lines.len() && lines_consumed < join_limit {
        let line = lines[current_idx];
        let (part, continues, continuation_type) =
            extract_string_part(line, config, current_idx > start_idx);

        if current_idx == start_idx {
            if !part.is_empty() {
                joined_parts.push(part);
            }
            if !continues {
                lines_consumed += 1;
                break;
            }
        } else {
            if continuation_type == ContinuationType::Backslash
                || continuation_type == ContinuationType::PlusOperator
                || continuation_type == ContinuationType::Implicit
                || !part.is_empty()
            {
                joined_parts.push(part);
            }
            if !continues {
                lines_consumed += 1;
                break;
            }
        }

        lines_consumed += 1;
        current_idx += 1;
    }

    let joined = joined_parts.join("");
    let mappings = if joined.is_empty() {
        Vec::new()
    } else {
        vec![LineMapping {
            start_offset: base_offset,
            end_offset: base_offset + joined.len(),
            line_number: original_start_line,
            original_start_offset: source_line_offset_or_record_gap(source_line_offsets, start_idx),
        }]
    };

    (joined, lines_consumed, mappings)
}
