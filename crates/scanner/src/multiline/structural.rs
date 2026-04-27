use super::config::LineMapping;
use super::preprocessor::extract_prefix;
use crate::fragment_cache::FragmentCache;
use regex::Regex;

pub(super) fn collect_structural_fragments(
    lines: &[&str],
    initial_offset: usize,
    fragment_cache: &FragmentCache,
) -> (Vec<String>, Vec<LineMapping>) {
    static ASSIGN_RE: std::sync::LazyLock<Option<Regex>> = std::sync::LazyLock::new(|| {
        Regex::new(r#"(?i)([a-z0-9_-]{2,32})\s*[:=]\s*["'`]([a-zA-Z0-9/+=_-]{4,})["'`](?:;|,)?$"#)
            .ok()
    });
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
        if line.contains('[') && line.contains(']') {
            let array_joined = join_inline_array_strings(line);
            if array_joined.len() >= 16 {
                structural_joined.push(array_joined.clone());
                structural_mappings.push(LineMapping {
                    start_offset: current_struct_offset,
                    end_offset: current_struct_offset + array_joined.len(),
                    line_number: index + 1,
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

    // Second pass: reassemble explicit `+`-concatenation expressions like
    //   `aws_key = aws_prefix + aws_suffix`
    // by resolving each identifier on the RHS to its earlier literal value.
    // This catches splits whose variable names share no common prefix
    // (audit gap: 2-fragment AWS reassembly — release-2026-04-26).
    //
    // We deliberately use a synthetic high `line_number` so these entries
    // don't merge with original-text line ranges in `line_window_offsets`
    // (which iterates ALL mappings and would otherwise pick a window that
    // spans both the original RHS line and the appended joined region).
    // Findings on these entries lose precise line attribution but still
    // surface the secret — better than the previous behavior of missing it
    // entirely.
    const SYNTHETIC_BASE_LINE: usize = 1_000_000_000;
    for (offset_idx, (_index, joined)) in lines
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
        });
        current_struct_offset += joined.len() + 1;
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
    static CONCAT_RE: std::sync::LazyLock<Option<Regex>> = std::sync::LazyLock::new(|| {
        Regex::new(
            r#"(?i)^\s*[a-z0-9_\-\.]{2,64}\s*[:=]\s*([a-z0-9_\-]{2,32}(?:\s*\+\s*[a-z0-9_\-]{2,32}){1,8})\s*;?\s*$"#,
        )
        .ok()
    });
    let re = CONCAT_RE.as_ref()?;
    let caps = re.captures(line)?;
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
    Some(joined)
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
