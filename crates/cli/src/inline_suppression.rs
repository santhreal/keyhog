//! Inline suppression handling for CLI findings.

use keyhog_core::{Chunk, RawMatch};
use std::collections::HashMap;

const INLINE_CONTEXT_PREV_LINE: &str = "__keyhog_internal_inline_prev_line_v1";
const INLINE_CONTEXT_CURRENT_LINE: &str = "__keyhog_internal_inline_current_line_v1";
const INLINE_SUPPRESSION_DIRECTIVES: &[&str] = &[
    "keyhog:ignore",
    "keyhog:allow",
    "gitleaks:allow",
    "betterleaks:allow",
];
const DETECTOR_DIRECTIVE_PREFIX: &str = "detector=";
const INLINE_COMMENT_MARKERS: &[&str] = &["//", "#", "--", "/*", "<!--"];

pub(crate) fn filter_inline_suppressions(matches: Vec<RawMatch>) -> Vec<RawMatch> {
    use std::io::BufRead;

    let mut filtered_matches = Vec::new();
    let mut files_to_matches: HashMap<String, Vec<RawMatch>> = HashMap::new();
    let mut non_file_matches = Vec::new();

    for mut m in matches {
        if let Some((prev_line, current_line)) = take_inline_context(&mut m) {
            if !is_inline_suppressed_buffered(&prev_line, &current_line, &m.detector_id) {
                filtered_matches.push(m);
            }
            continue;
        }
        if m.location.source.as_ref() == "filesystem" {
            if let Some(path) = m.location.file_path.clone() {
                files_to_matches
                    .entry(path.to_string())
                    .or_default()
                    .push(m);
                continue;
            }
        }
        non_file_matches.push(m);
    }

    filtered_matches.extend(non_file_matches);
    for (path, mut file_matches) in files_to_matches {
        file_matches.sort_by_key(|m| m.location.line.unwrap_or(0)); // LAW10: empty/absent => documented numeric default, recall-safe

        match std::fs::File::open(&path) {
            Ok(file) => {
                let mut reader = std::io::BufReader::new(file);
                let mut line_buf = String::new();
                let mut current_line_num = 1;
                let mut prev_line = String::new();
                let mut current_line = String::new();

                let mut file_matches = file_matches.into_iter();
                'findings: while let Some(m) = file_matches.next() {
                    let Some(target_line) = m.location.line else {
                        filtered_matches.push(m);
                        continue;
                    };

                    while current_line_num <= target_line {
                        line_buf.clear();
                        match reader.read_line(&mut line_buf) {
                            Ok(n) if n > 0 => {
                                // Trim trailing newline for the directive check.
                                let line = line_buf.trim_end_matches(['\n', '\r']).to_string();
                                prev_line = std::mem::replace(&mut current_line, line);
                                current_line_num += 1;
                            }
                            Ok(_) => break,
                            Err(error) => {
                                tracing::warn!(
                                    path = %path,
                                    line = current_line_num,
                                    target_line,
                                    %error,
                                    "failed reading inline suppression context; keeping current and remaining findings unsuppressed"
                                );
                                filtered_matches.push(m);
                                filtered_matches.extend(file_matches);
                                break 'findings;
                            }
                        }
                    }

                    if !is_inline_suppressed_buffered(&prev_line, &current_line, &m.detector_id) {
                        filtered_matches.push(m);
                    }
                }
            }
            Err(error) => {
                tracing::warn!(
                    path = %path,
                    %error,
                    "failed opening file for inline suppression context; keeping findings unsuppressed"
                );
                filtered_matches.extend(file_matches);
            }
        }
    }

    filtered_matches
}

pub(crate) fn attach_inline_suppression_context(chunks: &[Chunk], per_chunk: &mut [Vec<RawMatch>]) {
    for (chunk_index, matches) in per_chunk.iter_mut().enumerate() {
        let Some(primary_chunk) = chunks.get(chunk_index) else {
            continue;
        };
        for m in matches {
            attach_inline_suppression_context_to_match(chunks, primary_chunk, m);
        }
    }
}

pub(crate) fn attach_inline_suppression_context_to_matches(
    chunk: &Chunk,
    matches: &mut [RawMatch],
) {
    for m in matches {
        attach_inline_suppression_context_from_chunk(chunk, m);
    }
}

fn attach_inline_suppression_context_to_match(
    chunks: &[Chunk],
    primary_chunk: &Chunk,
    m: &mut RawMatch,
) {
    if attach_inline_suppression_context_from_chunk(primary_chunk, m) {
        return;
    }
    if primary_chunk.metadata.source_type != "filesystem" || primary_chunk.metadata.path.is_none() {
        return;
    }
    for candidate in chunks {
        if !same_filesystem_chunk_identity(primary_chunk, candidate) {
            continue;
        }
        if attach_inline_suppression_context_from_chunk(candidate, m) {
            return;
        }
    }
}

fn attach_inline_suppression_context_from_chunk(chunk: &Chunk, m: &mut RawMatch) -> bool {
    if chunk.metadata.source_type != "filesystem" || chunk.metadata.path.is_none() {
        return false;
    }
    let text = chunk.data.as_ref();
    let Some(relative_offset) = m.location.offset.checked_sub(chunk.metadata.base_offset) else {
        return false;
    };
    let Some((prev_line, current_line)) = line_context_at_offset(text, relative_offset) else {
        return false;
    };
    m.companions
        .insert(INLINE_CONTEXT_PREV_LINE.to_string(), prev_line);
    m.companions
        .insert(INLINE_CONTEXT_CURRENT_LINE.to_string(), current_line);
    true
}

fn same_filesystem_chunk_identity(left: &Chunk, right: &Chunk) -> bool {
    left.metadata.source_type == "filesystem"
        && right.metadata.source_type == "filesystem"
        && left.metadata.path.as_deref() == right.metadata.path.as_deref()
}

fn take_inline_context(m: &mut RawMatch) -> Option<(String, String)> {
    let prev_line = m.companions.remove(INLINE_CONTEXT_PREV_LINE);
    let current_line = m.companions.remove(INLINE_CONTEXT_CURRENT_LINE);
    if prev_line.is_some() || current_line.is_some() {
        let prev_line = match prev_line {
            Some(line) => line,
            None => String::new(),
        };
        let current_line = match current_line {
            Some(line) => line,
            None => String::new(),
        };
        Some((prev_line, current_line))
    } else {
        None
    }
}

fn line_context_at_offset(text: &str, offset: usize) -> Option<(String, String)> {
    if offset > text.len() || !text.is_char_boundary(offset) {
        return None;
    }

    let current_start = text[..offset].rfind('\n').map_or(0, |idx| idx + 1);
    let current_end = text[offset..]
        .find('\n')
        .map_or(text.len(), |idx| offset + idx);
    let current_line = trim_cr(&text[current_start..current_end]).to_string();

    let prev_line = if current_start == 0 {
        String::new()
    } else {
        let mut prev_end = current_start - 1;
        if prev_end > 0 && text.as_bytes()[prev_end - 1] == b'\r' {
            prev_end -= 1;
        }
        let prev_start = text[..prev_end].rfind('\n').map_or(0, |idx| idx + 1);
        text[prev_start..prev_end].to_string()
    };

    Some((prev_line, current_line))
}

fn trim_cr(line: &str) -> &str {
    match line.strip_suffix('\r') {
        Some(trimmed) => trimmed,
        None => line,
    }
}

fn is_inline_suppressed_buffered(prev_line: &str, current_line: &str, detector_id: &str) -> bool {
    line_has_inline_suppression(prev_line, detector_id)
        || line_has_inline_suppression(current_line, detector_id)
}

fn line_has_inline_suppression(line: &str, detector_id: &str) -> bool {
    let Some(directive) = inline_suppression_directive(line) else {
        return false;
    };
    // `directive` is already lowercased by `inline_suppression_directive`
    // (it operates on a lowercased copy of the line). Compare the
    // `detector=` token case-insensitively against `detector_id` rather
    // than allocating a lowercased copy of the id on every match - this
    // runs once per finding in the suppression hot path.
    match directive
        .split(|ch: char| ch.is_whitespace() || matches!(ch, ',' | ';'))
        .find_map(|token| token.strip_prefix(DETECTOR_DIRECTIVE_PREFIX))
    {
        Some(expected) => expected.eq_ignore_ascii_case(detector_id),
        None => true,
    }
}

fn inline_suppression_directive(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let directive = comment_segments(&lower).find_map(extract_directive_from_comment);
    directive
}

fn comment_segments(line: &str) -> impl Iterator<Item = &str> {
    INLINE_COMMENT_MARKERS
        .iter()
        .filter_map(|marker| line.find(marker).map(|index| &line[index + marker.len()..]))
}

fn extract_directive_from_comment(comment: &str) -> Option<String> {
    for &dir in INLINE_SUPPRESSION_DIRECTIVES {
        if let Some(directive_index) = comment.find(dir) {
            if comment[..directive_index]
                .chars()
                .any(|character| !character.is_whitespace())
            {
                continue;
            }
            let directive = &comment[directive_index..];
            return Some(directive.to_string());
        }
    }
    None
}
