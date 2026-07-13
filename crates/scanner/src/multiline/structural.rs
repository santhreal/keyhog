use super::config::{
    has_empty_string_join_marker, source_line_offset_or_record_gap,
    starts_parenthesized_implicit_block, LineMapping,
};
use super::string_extract::{
    extract_prefix, extract_quoted_content, fragment_assignment_name_is_credential_like,
};
use crate::fragment_cache::FragmentCache;
use crate::shared_regexes::ASSIGN_RE;
use regex::Regex;
use std::sync::LazyLock;

/// Variable-reference concatenation pattern: `lhs = ident (+ ident){1,8}`, RHS
/// captured. Single owner for both `resolve_concat_reference` (uses the capture)
/// and `config::has_var_ref_concat_line` (uses `is_match`; the capture group is
/// inert for a presence test), so the two call sites can never drift.
// Law 10 (build-bug ⇒ fail closed): both of these regexes are COMPILE-TIME
// CONSTANT patterns baked into the binary, no user/attacker input reaches
// `Regex::new`. A constant pattern either always compiles or never does, so a
// failure is a BUILD defect (someone edited the literal into an invalid regex),
// not a runtime condition. The old path called `warn_prefilter_disabled` and
// returned `None`, which SILENTLY DISABLED the multiline var-reference /
// template-interpolation reassembly surface for the whole process, a recall
// hole hidden behind one log line. PANIC in the initializer instead so the
// defect is caught at first use and can never ship as a quietly-degraded
// scanner. (`warn_prefilter_disabled` + `None` remains correct only for
// USER-supplied / data-driven patterns that can legitimately be malformed at
// runtime, not for these compiled-in literals.)
pub(super) static CONCAT_RE: LazyLock<Regex> = LazyLock::new(|| {
    let pattern = r#"(?i)^\s*[a-z0-9_\-\.]{2,64}\s*[:=]\s*([a-z0-9_\-]{2,32}(?:\s*\+\s*[a-z0-9_\-]{2,32}){1,8})\s*;?\s*$"#;
    match Regex::new(pattern) {
        Ok(re) => re,
        Err(error) => panic!(
            "multiline concatenation regex (CONCAT_RE) is a compiled-in constant \
             and failed to build: {error}. Fix the pattern literal."
        ),
    }
});

static TVAR_RE: LazyLock<Regex> = LazyLock::new(|| {
    let pattern = r#"(?i)([a-z0-9_$]{1,32})\s*[:=]\s*["'`]([a-zA-Z0-9/+=_\-\.]{2,})["'`]\s*;?\s*$"#;
    match Regex::new(pattern) {
        Ok(re) => re,
        Err(error) => panic!(
            "multiline template-variable regex (TVAR_RE) is a compiled-in constant \
             and failed to build: {error}. Fix the pattern literal."
        ),
    }
});

pub(super) fn warm_runtime_regexes() {
    LazyLock::force(&CONCAT_RE); // eager init (warm-up); fail-closed on build defect
    LazyLock::force(&TVAR_RE); // eager init (warm-up); fail-closed on build defect
}

pub(super) fn collect_structural_fragments(
    lines: &[&str],
    source_line_offsets: &[usize],
    initial_offset: usize,
    fragment_cache: &FragmentCache,
) -> (Vec<String>, Vec<LineMapping>) {
    let assign_re = &*ASSIGN_RE;

    // Minimum length for a reassembled cross-line fragment (parenthesized
    // implicit block, `+`-concat reference, template interpolation, or
    // prefix-grouped cluster) to be worth emitting. All four structural passes
    // share this floor; one owner so they can never drift apart. The inline
    // ARRAY path uses its own larger `MIN_INLINE_ARRAY_FRAGMENT_LEN` cutoff and
    // is intentionally separate.
    const MIN_STRUCTURAL_FRAGMENT_LEN: usize = 12;
    // Minimum length for a reassembled inline-array string fragment (e.g.
    // `key = ["ab", "cd", ...]`). Deliberately larger than the cross-line floor:
    // a single joined array literal has no cross-line evidence backing it, so it
    // must clear a higher bar before it is emitted as a scan candidate.
    const MIN_INLINE_ARRAY_FRAGMENT_LEN: usize = 16;
    // Maximum line gap between two credential-like assignments for them to stay
    // in the same reassembly cluster. A later assignment further than this from
    // the cluster's last member starts a fresh cluster instead of extending it.
    const MAX_CLUSTER_LINE_GAP: usize = 10;

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
        if let Some(target_name) = inline_array_assignment_name(line) {
            let (array_joined, contains_only_static_strings) = join_inline_array_strings(line);
            let target_is_credential = fragment_assignment_name_is_credential_like(target_name);
            let joined_has_known_prefix =
                crate::confidence::known_prefix_confidence_floor(&array_joined).is_some();
            let known_prefix_static_join = contains_only_static_strings
                && inline_array_has_matching_empty_join(line)
                && joined_has_known_prefix;
            if array_joined.len() >= MIN_INLINE_ARRAY_FRAGMENT_LEN
                && (target_is_credential || known_prefix_static_join)
            {
                structural_joined.push(array_joined.clone());
                structural_mappings.push(LineMapping {
                    start_offset: current_struct_offset,
                    end_offset: current_struct_offset + array_joined.len(),
                    line_number: index + 1,
                    original_start_offset: source_line_offset_or_record_gap(
                        source_line_offsets,
                        index,
                    ),
                    transport_decoded: false,
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
                        if index.saturating_sub(last.0) < MAX_CLUSTER_LINE_GAP {
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
        .filter(|(_, joined)| joined.len() >= MIN_STRUCTURAL_FRAGMENT_LEN)
    {
        structural_joined.push(joined.clone());
        structural_mappings.push(LineMapping {
            start_offset: current_struct_offset,
            end_offset: current_struct_offset + joined.len(),
            line_number: start_line,
            original_start_offset: source_line_offset_or_record_gap(
                source_line_offsets,
                start_line.saturating_sub(1),
            ),
            transport_decoded: false,
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
    // Distinct base so template-pass synthetic line numbers never collide with a
    // concat-pass entry (`SYNTHETIC_BASE_LINE + 0`), which would merge two
    // unrelated reassembled fragments into one line window in
    // `line_window_offsets`.
    const SYNTHETIC_TEMPLATE_BASE_LINE: usize = 2_000_000_000;
    for (offset_idx, (index, joined)) in lines
        .iter()
        .enumerate()
        .filter_map(|(i, line)| resolve_concat_reference(line, &var_values).map(|j| (i, j)))
        .filter(|(_, j)| j.len() >= MIN_STRUCTURAL_FRAGMENT_LEN)
        .enumerate()
    {
        structural_joined.push(joined.clone());
        structural_mappings.push(LineMapping {
            start_offset: current_struct_offset,
            end_offset: current_struct_offset + joined.len(),
            line_number: SYNTHETIC_BASE_LINE + offset_idx,
            original_start_offset: source_line_offset_or_record_gap(source_line_offsets, index),
            transport_decoded: false,
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
        for (offset_idx, (index, joined)) in lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| {
                resolve_template_reference(line, &tmpl_vars).map(|joined| (index, joined))
            })
            .filter(|(_, joined)| joined.len() >= MIN_STRUCTURAL_FRAGMENT_LEN)
            .enumerate()
        {
            structural_joined.push(joined.clone());
            structural_mappings.push(LineMapping {
                start_offset: current_struct_offset,
                end_offset: current_struct_offset + joined.len(),
                line_number: SYNTHETIC_TEMPLATE_BASE_LINE + offset_idx,
                original_start_offset: source_line_offset_or_record_gap(source_line_offsets, index),
                transport_decoded: false,
            });
            current_struct_offset += joined.len() + 1;
        }
    }

    for cluster in clusters {
        if cluster.len() >= 2 {
            let joined: String = cluster.iter().map(|(_, _, value)| value.as_str()).collect();
            if joined.len() >= MIN_STRUCTURAL_FRAGMENT_LEN {
                let start_line = cluster[0].0 + 1;
                structural_joined.push(joined.clone());
                structural_mappings.push(LineMapping {
                    start_offset: current_struct_offset,
                    end_offset: current_struct_offset + joined.len(),
                    line_number: start_line,
                    original_start_offset: source_line_offset_or_record_gap(
                        source_line_offsets,
                        start_line.saturating_sub(1),
                    ),
                    transport_decoded: false,
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
    let caps = CONCAT_RE.captures(line)?;
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
pub(crate) fn resolve_template_reference(
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
            let mut in_str: Option<char> = None;
            for c in chars.by_ref() {
                // Track string spans so a `{`/`}` inside a quoted literal
                // (`${"a}b"}`) does not miscount the brace depth and end the
                // interpolation early, mirrors the string-aware skip in
                // string_extract::extract_template_literal_continuation.
                if let Some(q) = in_str {
                    if c == q {
                        in_str = None;
                    }
                } else if c == '"' || c == '\'' || c == '`' {
                    in_str = Some(c);
                } else if c == '{' {
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
    for line in lines {
        if let Some(caps) = TVAR_RE.captures(line) {
            if let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) {
                map.insert(name.as_str().to_string(), value.as_str().to_string());
            }
        }
    }
    map
}

fn is_related_variable(v1: &str, v2: &str) -> bool {
    v1 == v2 || extract_prefix(v1) == extract_prefix(v2)
}

fn join_inline_array_strings(line: &str) -> (String, bool) {
    // Only join the quoted literals INSIDE the `[...]` array body. Scanning the
    // whole line would splice a quoted LHS key (`"api_key": ["a", "b"]`) or a
    // bare single-string assignment (`key = "value"`, no array) into the
    // reassembled candidate, corrupting the value and emitting phantom
    // duplicates of secrets the per-line chain already handles. No `[` means
    // this is not an inline array.
    let Some(open) = line.find('[') else {
        return (String::new(), false);
    };
    let (inner, closed) = match line.rfind(']') {
        Some(close) if close > open => (&line[open + 1..close], true),
        _ => (&line[open + 1..], false),
    };

    let mut array_joined = String::new();
    let mut in_str = false;
    let mut quote_char = '\0';
    let mut current_str = String::new();
    let mut escaped = false;
    let mut contains_only_static_strings = closed;

    for ch in inner.chars() {
        if !in_str {
            if ch == '"' || ch == '\'' || ch == '`' {
                in_str = true;
                quote_char = ch;
                escaped = false;
            } else if !ch.is_whitespace() && ch != ',' {
                contains_only_static_strings = false;
            }
        } else if escaped {
            current_str.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
            current_str.push(ch);
        } else if ch == quote_char {
            in_str = false;
            array_joined.push_str(&current_str);
            current_str.clear();
        } else {
            current_str.push(ch);
        }
    }

    if in_str || (inner.contains("${") && inner.contains('`')) {
        contains_only_static_strings = false;
    }

    (array_joined, contains_only_static_strings)
}

/// Require the empty `.join("")` to consume the exact array being recovered.
/// This prevents an unrelated join elsewhere in a multiline chunk from
/// authorizing a known-prefix array that uses a non-empty separator or is never
/// joined at all.
fn inline_array_has_matching_empty_join(line: &str) -> bool {
    let Some(open) = line.find('[') else {
        return false;
    };
    let Some(close) = line.rfind(']').filter(|close| *close > open) else {
        return false;
    };
    let after_array = &line[close + 1..];

    let direct_suffix = after_array.trim_start();
    if direct_suffix.starts_with(".join") && has_empty_string_join_marker(direct_suffix) {
        return true;
    }

    let before_array = &line[..open];
    let Some(separator) = before_array.rfind(['=', ':']) else {
        return false;
    };
    let binding = before_array[..separator]
        .rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$')))
        .find(|part| !part.is_empty());
    let Some(binding) = binding else {
        return false;
    };

    after_array.match_indices(binding).any(|(index, _)| {
        let boundary_before = index == 0
            || !after_array.as_bytes()[index - 1].is_ascii_alphanumeric()
                && !matches!(after_array.as_bytes()[index - 1], b'_' | b'$');
        let suffix = &after_array[index + binding.len()..];
        let boundary_after = suffix
            .as_bytes()
            .first()
            .is_none_or(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'$'));
        let suffix = suffix.trim_start();
        boundary_before
            && boundary_after
            && suffix.starts_with(".join")
            && has_empty_string_join_marker(suffix)
    })
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
