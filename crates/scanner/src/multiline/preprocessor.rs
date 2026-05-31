use super::config::{should_passthrough, LineMapping, MultilineConfig, PreprocessedText};
use super::structural::collect_structural_fragments;
use crate::fragment_cache::FragmentCache;

#[derive(Debug, PartialEq)]
enum ContinuationType {
    None,
    Backslash,
    PlusOperator,
    Implicit,
    TemplateLiteral,
}

/// Join adjacent string fragments and continuations before scanning.
pub fn preprocess_multiline(
    text: &str,
    config: &MultilineConfig,
    fragment_cache: &FragmentCache,
) -> PreprocessedText {
    if should_passthrough(text) {
        return passthrough_text(text);
    }

    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return PreprocessedText {
            text: String::new(),
            original_end: 0,
            mappings: Vec::new(),
        };
    }

    let first_nonwhite = text.trim_start().chars().next().unwrap_or(' ');
    if first_nonwhite == '{' || first_nonwhite == '[' {
        return passthrough_text(text);
    }

    let mut result_lines = Vec::new();
    let mut mappings = Vec::new();
    let mut current_offset = 0usize;
    let mut index = 0;
    while index < lines.len() {
        let (joined_line, lines_consumed, line_mappings) =
            process_line_chain(&lines, index, config, current_offset);

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
    let structural_base = if will_append {
        original_end + 1 + 1 + joined_text.len()
    } else {
        original_end + 1
    };
    let (structural_joined, structural_mappings) =
        collect_structural_fragments(&lines, structural_base, fragment_cache);

    // Delay the full-chunk `text.to_string()` copy until we know there is
    // actually something to append. When neither a real concatenation join nor
    // a structural fragment was found (the common case for a chunk that merely
    // tripped a concatenation indicator), `final_text` would equal the input
    // verbatim, so we skip pushing `joined_text`/structural segments into a new
    // buffer. The chain `mappings` are still emitted unshifted (matching the
    // original path, which only shifts them when the join is appended) so the
    // offset→line map is byte-identical to the eager-copy result.
    if !will_append && structural_joined.is_empty() {
        let mut original_mappings = identity_line_mappings(text, original_end);
        original_mappings.extend(mappings);
        return PreprocessedText {
            text: text.to_string(),
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
        text: final_text,
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
        });
        offset = end + 1;
    }
    original_mappings
}

fn passthrough_text(text: &str) -> PreprocessedText {
    let mut mappings = Vec::new();
    let mut offset = 0;
    for (index, line) in text.lines().enumerate() {
        mappings.push(LineMapping {
            line_number: index + 1,
            start_offset: offset,
            end_offset: offset + line.len(),
        });
        offset += line.len() + 1;
    }
    PreprocessedText {
        text: text.to_string(),
        original_end: text.len(),
        mappings,
    }
}

fn process_line_chain(
    lines: &[&str],
    start_idx: usize,
    config: &MultilineConfig,
    base_offset: usize,
) -> (String, usize, Vec<LineMapping>) {
    let mut joined_parts = Vec::new();
    let mut current_idx = start_idx;
    let original_start_line = start_idx + 1;

    while current_idx < lines.len() && (current_idx - start_idx) < config.max_join_lines {
        let line = lines[current_idx];
        let (part, continues, continuation_type) =
            extract_string_part(line, config, current_idx > start_idx);

        if current_idx == start_idx {
            if !part.is_empty() {
                joined_parts.push(part);
            }
            if !continues {
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
                break;
            }
        }

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
        }]
    };

    let lines_consumed = (current_idx - start_idx) + 1;
    (joined, lines_consumed, mappings)
}

pub(crate) fn extract_prefix(var_name: &str) -> String {
    var_name
        .to_lowercase()
        .replace("part", "")
        .replace(['_', '-'], "")
        .trim_end_matches(|ch: char| ch.is_ascii_digit())
        .to_string()
}

fn extract_string_part(
    line: &str,
    config: &MultilineConfig,
    is_continuation: bool,
) -> (String, bool, ContinuationType) {
    let trimmed = line.trim();

    if config.backslash_continuation && trimmed.ends_with('\\') && !trimmed.ends_with("\\\\") {
        let without_backslash = line
            .trim_end()
            .strip_suffix('\\')
            .unwrap_or(line)
            .trim_end();
        if config.plus_concatenation && without_backslash.trim().contains('+') {
            if let Some((part, _)) = extract_plus_concatenation(without_backslash) {
                return (part, true, ContinuationType::Backslash);
            }
        }
        let part = extract_string_content(without_backslash);
        return (part, true, ContinuationType::Backslash);
    }

    if let Some((part, continues)) = extract_function_concatenation(line) {
        return (part, continues, ContinuationType::Implicit);
    }

    if config.plus_concatenation {
        if let Some((part, continues)) = extract_plus_concatenation(line) {
            return (part, continues, ContinuationType::PlusOperator);
        }
    }

    if config.python_implicit {
        if let Some((part, continues)) = extract_python_implicit_concatenation(line) {
            return (part, continues, ContinuationType::Implicit);
        }
    }

    if config.template_literals {
        if let Some((part, continues)) = extract_template_literal_continuation(line) {
            return (part, continues, ContinuationType::TemplateLiteral);
        }
    }

    if is_continuation {
        (extract_string_content(line), false, ContinuationType::None)
    } else {
        (line.to_string(), false, ContinuationType::None)
    }
}

fn extract_string_content(line: &str) -> String {
    let trimmed = line.trim().trim_end_matches([';', ',', ' ']);
    for (open, close) in [('"', '"'), ('\'', '\''), ('`', '`')] {
        if let Some(content) = extract_quoted_content(trimmed, open, close) {
            return content;
        }
    }
    filter_line_content(trimmed)
}

pub(crate) fn extract_quoted_content(s: &str, open: char, close: char) -> Option<String> {
    let mut chars = s.chars().peekable();
    let mut is_fstring = false;
    while let Some(&ch) = chars.peek() {
        if ch == open {
            break;
        }
        if ch == 'f' || ch == 'F' {
            is_fstring = true;
        }
        chars.next();
    }

    if chars.next() != Some(open) {
        return None;
    }

    let mut content = String::new();
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if escaped {
            content.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
            content.push(ch);
        } else if ch == close {
            return Some(content);
        } else if is_fstring && ch == '{' && chars.peek() != Some(&'{') {
            let mut brace_depth = 1;
            for c in chars.by_ref() {
                if c == '{' {
                    brace_depth += 1;
                } else if c == '}' {
                    brace_depth -= 1;
                    if brace_depth == 0 {
                        break;
                    }
                }
            }
        } else {
            content.push(ch);
        }
    }

    None
}

fn filter_line_content(line: &str) -> String {
    let line = line
        .trim_start_matches("const ")
        .trim_start_matches("let ")
        .trim_start_matches("var ")
        .trim_start_matches("val ")
        .trim_start_matches("final ")
        .trim_start_matches("static ")
        .trim_start_matches("string ")
        .trim_start_matches("String ")
        .trim_start_matches("auto ")
        .trim_start_matches("dim ")
        .trim_start_matches("my ");

    if let Some(pos) = line.find(" = ") {
        return line[pos + 3..].trim().to_string();
    }
    if let Some(pos) = line.find("= ") {
        return line[pos + 2..].trim().to_string();
    }
    if let Some(pos) = line.find('=') {
        return line[pos + 1..].trim().to_string();
    }

    line.to_string()
}

fn extract_plus_concatenation(line: &str) -> Option<(String, bool)> {
    let trimmed = line.trim();
    let ends_with_plus = trimmed.ends_with('+');
    if !trimmed.contains('+') {
        return None;
    }

    let content_to_split = if let Some(pos) = trimmed.find('=') {
        &trimmed[pos + 1..]
    } else {
        trimmed
    };

    let parts: Vec<&str> = content_to_split.split('+').collect();
    if parts.len() < 2 && !ends_with_plus {
        return None;
    }

    let mut result = String::new();
    for part in &parts {
        let content = extract_string_content(part.trim());
        if !content.is_empty() {
            result.push_str(&content);
        }
    }

    if result.is_empty() {
        None
    } else {
        Some((result, ends_with_plus))
    }
}

fn extract_python_implicit_concatenation(line: &str) -> Option<(String, bool)> {
    let chars: Vec<char> = line.chars().collect();
    let mut parts = Vec::new();
    let mut index = 0;
    let mut last_end = None;

    while index < chars.len() {
        if chars[index] == '"' || chars[index] == '\'' {
            let quote = chars[index];
            let start = index;
            let mut j = index + 1;
            let mut content = String::new();
            let mut escaped = false;
            let mut closed = false;

            while j < chars.len() {
                if escaped {
                    content.push(chars[j]);
                    escaped = false;
                } else if chars[j] == '\\' {
                    escaped = true;
                    content.push(chars[j]);
                } else if chars[j] == quote {
                    closed = true;
                    break;
                } else {
                    content.push(chars[j]);
                }
                j += 1;
            }

            if closed {
                if let Some(prev_end) = last_end {
                    let gap = &chars[prev_end + 1..start];
                    if gap.iter().any(|&c| !c.is_whitespace()) {
                        return None;
                    }
                }
                parts.push(content);
                last_end = Some(j);
                index = j;
            }
        }
        index += 1;
    }

    if parts.len() < 2 {
        return None;
    }
    Some((parts.join(""), false))
}

fn extract_function_concatenation(line: &str) -> Option<(String, bool)> {
    let trimmed = line.trim();
    if !trimmed.contains("paste0(") && !trimmed.contains("paste(") && !trimmed.contains("concat!(")
    {
        return None;
    }
    let parts = extract_quoted_strings(trimmed);
    if parts.len() < 2 {
        return None;
    }
    Some((parts.join(""), false))
}

fn extract_quoted_strings(line: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut index = 0;
    let chars: Vec<char> = line.chars().collect();

    while index < chars.len() {
        if chars[index] == '"' || chars[index] == '\'' {
            let quote = chars[index];
            let mut j = index + 1;
            let mut content = String::new();
            let mut escaped = false;

            while j < chars.len() {
                if escaped {
                    content.push(chars[j]);
                    escaped = false;
                } else if chars[j] == '\\' {
                    escaped = true;
                    content.push(chars[j]);
                } else if chars[j] == quote {
                    parts.push(content);
                    index = j;
                    break;
                } else {
                    content.push(chars[j]);
                }
                j += 1;
            }
        }
        index += 1;
    }

    parts
}

fn extract_template_literal_continuation(line: &str) -> Option<(String, bool)> {
    let trimmed = line.trim();
    if !trimmed.contains('`') {
        return None;
    }

    let continues = trimmed.chars().filter(|&ch| ch == '`').count() % 2 == 1;
    let mut result = String::new();
    let mut in_template = false;
    let mut chars = trimmed.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '`' {
            in_template = !in_template;
            continue;
        }
        if in_template && ch == '$' && chars.peek() == Some(&'{') {
            chars.next();
            // Inside a `${...}` interpolation, string-literal contents ARE
            // concatenation fragments: `ghp_${"BODY"}` reassembles to
            // `ghp_BODY`. Pull the bytes inside any "..."/'...'/`...` and
            // append them; everything else (bare identifiers like
            // `${token}`, operators, whitespace) is a runtime expression,
            // not literal text, so it's skipped - which keeps variable
            // references from polluting the reassembled candidate.
            let mut brace_depth = 1;
            let mut in_str: Option<char> = None;
            for c in chars.by_ref() {
                if let Some(q) = in_str {
                    if c == q {
                        in_str = None;
                    } else {
                        result.push(c);
                    }
                    continue;
                }
                match c {
                    '"' | '\'' | '`' => in_str = Some(c),
                    '{' => brace_depth += 1,
                    '}' => {
                        brace_depth -= 1;
                        if brace_depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            continue;
        }
        if in_template {
            result.push(ch);
        }
    }

    Some((result, continues))
}
