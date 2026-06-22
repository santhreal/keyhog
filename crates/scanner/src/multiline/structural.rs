use super::config::{starts_parenthesized_implicit_block, LineMapping};
use super::string_extract::{
    extract_prefix, extract_quoted_content, fragment_assignment_name_is_credential_like,
};
use crate::fragment_cache::FragmentCache;
use crate::shared_regexes::ASSIGN_RE;
use regex::Regex;
use std::sync::LazyLock;

static CONCAT_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    match Regex::new(
        r#"(?i)^\s*[a-z0-9_\-\.]{2,64}\s*[:=]\s*([a-z0-9_\-]{2,32}(?:\s*\+\s*[a-z0-9_\-]{2,32}){1,8})\s*;?\s*$"#,
    ) {
        Ok(re) => Some(re),
        Err(error) => {
            crate::prefilter_degrade::warn_prefilter_disabled(
                "multiline concatenation regex (CONCAT_RE)",
                &error,
            );
            None
        }
    }
});

static TVAR_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    match Regex::new(
        r#"(?i)([a-z0-9_$]{1,32})\s*[:=]\s*["'`]([a-zA-Z0-9/+=_\-\.]{2,})["'`]\s*;?\s*$"#,
    ) {
        Ok(re) => Some(re),
        Err(error) => {
            crate::prefilter_degrade::warn_prefilter_disabled(
                "multiline template-variable regex (TVAR_RE)",
                &error,
            );
            None
        }
    }
});

pub(super) fn warm_runtime_regexes() {
    let _ = CONCAT_RE.as_ref(); // LAW10: forces lazy-static/regex eager init (warm-up); not a fallback
    let _ = TVAR_RE.as_ref(); // LAW10: forces lazy-static/regex eager init (warm-up); not a fallback
}

pub(super) fn collect_structural_fragments(
    lines: &[&str],
    source_line_offsets: &[usize],
    initial_offset: usize,
    fragment_cache: &FragmentCache,
) -> (Vec<String>, Vec<LineMapping>) {
    let Some(assign_re) = ASSIGN_RE.as_ref() else {
        return (Vec::new(), Vec::new());
    };

    let mut current_struct_offset = initial_offset;
    let mut structural_joined = Vec::new();
    let mut structural_mappings = Vec::new();
    let mut clusters: Vec<Vec<(usize, String, String)>> = Vec::new();
    let mut active_clusters: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    // Map from variable name → (line_index, literal value) for assignments
    // we've seen. Used by the concatenation-reference pass below to glue
    // splits whose variable names share no common prefix (e.g. `aws_prefix`
    // and `aws_suffix`) but are joined explicitly via `aws_key = aws_prefix
    // + aws_suffix`.
    let mut var_values: std::collections::HashMap<String, (usize, String)> =
        std::collections::HashMap::new();

    for (index, line) in lines.iter().enumerate() {
        if inline_array_assignment_name(line)
            .is_some_and(fragment_assignment_name_is_credential_like)
        {
            let array_joined = join_inline_array_strings(line);
            if array_joined.len() >= 16 {
                structural_joined.push(array_joined.clone());
                structural_mappings.push(LineMapping {
                    start_offset: current_struct_offset,
                    end_offset: current_struct_offset + array_joined.len(),
                    line_number: index + 1,
                    original_start_offset: source_line_offsets.get(index).copied().unwrap_or(0), // LAW10: reporting-only fallback for malformed synthetic line index
                });
                current_struct_offset += array_joined.len() + 1;
            }
        }

        if let Some(caps) = assign_re.captures(line) {
            let Some(var_name_match) = caps.get(1) else {
                continue;
            };
            let Some(value_match) = caps.get(2) else {
                continue;
            };
            let var_name = var_name_match.as_str();
            let value = value_match.as_str();
            var_values.insert(var_name.to_string(), (index, value.to_string()));
            if !fragment_assignment_name_is_credential_like(var_name) {
                continue;
            }
            let prefix = extract_prefix(var_name);
            let mut added = false;

            if let Some(&cluster_idx) = active_clusters.get(&prefix) {
                let cluster = &mut clusters[cluster_idx];
                if is_related_variable(&cluster[0].1, var_name) {
                    if let Some(last) = cluster.last() {
                        if index.saturating_sub(last.0) < 10 {
                            cluster.push((index, var_name.to_string(), value.to_string()));
                            added = true;
                        }
                    }
                }
            }

            if !added {
                let new_idx = clusters.len();
                clusters.push(vec![(index, var_name.to_string(), value.to_string())]);
                active_clusters.insert(prefix, new_idx);
            }
        }
    }

    // Python-style implicit concatenation also appears as a parenthesized block:
    //
    //   token = (
    //       "head"
    //       "middle"
    //       "tail"
    //   )
    //
    // The per-line chain joins explicit `+` and same-line implicit literals;
    // this structural pass owns the cross-line block shape.
    for (start_line, joined) in collect_parenthesized_implicit_blocks(lines)
        .into_iter()
        .filter(|(_, joined)| joined.len() >= 12)
    {
        structural_joined.push(joined.clone());
        structural_mappings.push(LineMapping {
            start_offset: current_struct_offset,
            end_offset: current_struct_offset + joined.len(),
            line_number: start_line,
            original_start_offset: source_line_offsets
                .get(start_line.saturating_sub(1))
                .copied()
                .unwrap_or(0), // LAW10: reporting-only fallback for malformed synthetic line index
        });
        current_struct_offset += joined.len() + 1;
    }

    // Second pass: reassemble explicit `+`-concatenation expressions like
    //   `aws_key = aws_prefix + aws_suffix`
    // by resolving each identifier on the RHS to its earlier literal value.
    // This catches splits whose variable names share no common prefix
    // (audit gap: 2-fragment AWS reassembly - release-2026-04-26).
    //
    // We deliberately use a synthetic high `line_number` so these entries
    // don't merge with original-text line ranges in `line_window_offsets`
    // (which iterates ALL mappings and would otherwise pick a window that
    // spans both the original RHS line and the appended joined region).
    // Findings on these entries lose precise line attribution but still
    // surface the secret - better than the previous behavior of missing it
    // entirely.
    const SYNTHETIC_BASE_LINE: usize = 1_000_000_000;
    for (offset_idx, (index, joined)) in lines
        .iter()
        .enumerate()
        .filter_map(|(i, line)| resolve_concat_reference(line, &var_values).map(|j| (i, j)))
        .filter(|(_, j)| j.len() >= 12)
        .enumerate()
    {
        structural_joined.push(joined.clone());
        structural_mappings.push(LineMapping {
            start_offset: current_struct_offset,
            end_offset: current_struct_offset + joined.len(),
            line_number: SYNTHETIC_BASE_LINE + offset_idx,
            original_start_offset: source_line_offsets.get(index).copied().unwrap_or(0), // LAW10: reporting-only fallback for malformed synthetic line index
        });
        current_struct_offset += joined.len() + 1;
    }

    // Third pass: template-literal variable interpolation.
    //   const a = "xoxb-";
    //   const b = "...";
    //   token = `${a}${b}`;
    // Resolve each `${ident}` / `${"lit"}` in a template RHS to its recorded
    // literal value and concatenate. Gated on the `}${` adjacent-interpolation
    // signal so ordinary single-interpolation template code never enters this
    // pass (keeps cold-path JS/TS scanning free of the cost).
    if lines.iter().any(|line| line.contains("}${")) {
        let tmpl_vars = collect_template_vars(lines);
        for (index, joined) in lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| {
                resolve_template_reference(line, &tmpl_vars).map(|joined| (index, joined))
            })
            .filter(|(_, joined)| joined.len() >= 12)
        {
            structural_joined.push(joined.clone());
            structural_mappings.push(LineMapping {
                start_offset: current_struct_offset,
                end_offset: current_struct_offset + joined.len(),
                line_number: SYNTHETIC_BASE_LINE,
                original_start_offset: source_line_offsets.get(index).copied().unwrap_or(0), // LAW10: reporting-only fallback for malformed synthetic line index
            });
            current_struct_offset += joined.len() + 1;
        }
    }

    for cluster in clusters {
        if cluster.len() >= 2 {
            let joined: String = cluster.iter().map(|(_, _, value)| value.as_str()).collect();
            if joined.len() >= 12 {
                let start_line = cluster[0].0 + 1;
                structural_joined.push(joined.clone());
                structural_mappings.push(LineMapping {
                    start_offset: current_struct_offset,
                    end_offset: current_struct_offset + joined.len(),
                    line_number: start_line,
                    original_start_offset: source_line_offsets
                        .get(start_line.saturating_sub(1))
                        .copied()
                        .unwrap_or(0), // LAW10: reporting-only fallback for malformed synthetic line index
                });
                current_struct_offset += joined.len() + 1;
            }
        }

        for (line_idx, var_name, value) in cluster {
            fragment_cache.record_and_reassemble(crate::fragment_cache::SecretFragment {
                prefix: extract_prefix(&var_name),
                var_name,
                value: zeroize::Zeroizing::new(value),
                line: line_idx + 1,
                path: None,
            });
        }
    }

    (structural_joined, structural_mappings)
}

/// Recognize `lhs = ident1 + ident2 [+ ident3 ...]` and resolve each ident
/// to its previously-recorded literal value. Returns the concatenated value
/// when at least two idents resolve and no non-ident token appears on the
/// RHS. Variable names match the same `[a-zA-Z0-9_-]{2,32}` shape used by
/// `ASSIGN_RE`.
fn resolve_concat_reference(
    line: &str,
    var_values: &std::collections::HashMap<String, (usize, String)>,
) -> Option<String> {
    let re = CONCAT_RE.as_ref()?;
    let caps = re.captures(line)?;
    let target_name = inline_array_assignment_name(line)?;
    let rhs = caps.get(1)?.as_str();
    let parts: Vec<&str> = rhs.split('+').map(str::trim).collect();
    if parts.len() < 2 {
        return None;
    }
    let mut joined = String::new();
    for ident in &parts {
        let value = var_values.get(*ident)?;
        joined.push_str(&value.1);
    }
    (concat_target_name_is_credential_like(target_name)
        || crate::confidence::known_prefix_confidence_floor(&joined).is_some())
    .then_some(joined)
}

fn concat_target_name_is_credential_like(var_name: &str) -> bool {
    let Some(normalized) =
        crate::engine::phase2_generic::keywords::normalize_assignment_keyword(var_name)
    else {
        return false;
    };
    crate::entropy::keywords::normalized_assignment_keyword_is_credential(&normalized)
        || crate::engine::phase2_generic::keywords::normalized_assignment_keyword_has_secret_suffix(
            &normalized,
        )
}

fn inline_array_assignment_name(line: &str) -> Option<&str> {
    let sep = line.find('=').or_else(|| line.find(':'))?;
    let lhs = &line[..sep];
    lhs.rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')))
        .find(|part| !part.is_empty())
}

/// Resolve a template-literal RHS like `` `${a}${b}` `` (or `` `${"lit"}` ``)
/// against a map of recorded variable literals. Each `${ident}` is replaced by
/// its value, `${"..."}`/`${'...'}` by the inner literal, and any literal text
/// in the template is kept verbatim. Returns `None` if any interpolation is an
/// unresolved reference (so a partial/garbage candidate is never emitted) or if
/// nothing was resolved.
fn resolve_template_reference(
    line: &str,
    vars: &std::collections::HashMap<String, String>,
) -> Option<String> {
    let trimmed = line.trim();
    let open = trimmed.find('`')?;
    let rest = &trimmed[open + 1..];
    let close = rest.find('`')?;
    let template = &rest[..close];
    if !template.contains("${") {
        return None;
    }

    let mut joined = String::new();
    let mut chars = template.chars().peekable();
    let mut resolved = 0usize;
    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut inner = String::new();
            let mut depth = 1;
            for c in chars.by_ref() {
                if c == '{' {
                    depth += 1;
                } else if c == '}' {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                inner.push(c);
            }
            let inner = inner.trim();
            if inner.len() >= 2
                && ((inner.starts_with('"') && inner.ends_with('"'))
                    || (inner.starts_with('\'') && inner.ends_with('\'')))
            {
                joined.push_str(&inner[1..inner.len() - 1]);
                resolved += 1;
            } else if let Some(value) = vars.get(inner) {
                joined.push_str(value);
                resolved += 1;
            } else {
                return None;
            }
        } else {
            joined.push(ch);
        }
    }

    (resolved >= 1).then_some(joined)
}

/// Collect `ident = "value"` assignments for the template-interpolation pass.
/// Unlike `ASSIGN_RE` this admits single-character names (`a`, `b`) and the
/// `$`-prefixed identifiers common in JS/TS, because template references are
/// frequently terse (`${a}`). Only built when the `}${` concat signal is
/// present, so the extra regex never runs on ordinary code.
fn collect_template_vars(lines: &[&str]) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    if let Some(re) = TVAR_RE.as_ref() {
        for line in lines {
            if let Some(caps) = re.captures(line) {
                if let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) {
                    map.insert(name.as_str().to_string(), value.as_str().to_string());
                }
            }
        }
    }
    map
}

fn is_related_variable(v1: &str, v2: &str) -> bool {
    v1 == v2 || extract_prefix(v1) == extract_prefix(v2)
}

fn join_inline_array_strings(line: &str) -> String {
    let mut array_joined = String::new();
    let mut in_str = false;
    let mut quote_char = '\0';
    let mut current_str = String::new();

    for ch in line.chars() {
        if !in_str {
            if ch == '"' || ch == '\'' || ch == '`' {
                in_str = true;
                quote_char = ch;
            }
        } else if ch == quote_char {
            in_str = false;
            array_joined.push_str(&current_str);
            current_str.clear();
        } else {
            current_str.push(ch);
        }
    }

    array_joined
}

const PARENTHESIZED_IMPLICIT_SCAN_LINES: usize = 16;

fn collect_parenthesized_implicit_blocks(lines: &[&str]) -> Vec<(usize, String)> {
    let mut blocks = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        if !starts_parenthesized_implicit_block(lines[index]) {
            index += 1;
            continue;
        }

        let mut parts = Vec::new();
        let mut first_literal_line = None;
        let mut cursor = index + 1;
        let mut closed_at = None;
        while cursor < lines.len()
            && cursor.saturating_sub(index) <= PARENTHESIZED_IMPLICIT_SCAN_LINES
        {
            let trimmed = lines[cursor].trim();
            if trimmed.starts_with(')') {
                closed_at = Some(cursor);
                break;
            }
            if trimmed.is_empty() {
                cursor += 1;
                continue;
            }
            let Some(part) = quoted_literal_line(trimmed) else {
                parts.clear();
                break;
            };
            first_literal_line.get_or_insert(cursor + 1);
            parts.push(part);
            cursor += 1;
        }

        if let Some(close_index) = closed_at {
            if parts.len() >= 2 {
                if let Some(start_line) = first_literal_line {
                    blocks.push((start_line, parts.concat()));
                }
            }
            index = close_index + 1;
        } else {
            index = cursor.max(index + 1);
        }
    }
    blocks
}

fn quoted_literal_line(trimmed: &str) -> Option<String> {
    let literal = trimmed.trim_end_matches(',').trim();
    if literal.starts_with('"') {
        return extract_quoted_content(literal, '"', '"');
    }
    if literal.starts_with('\'') {
        return extract_quoted_content(literal, '\'', '\'');
    }
    None
}
