use crate::types::MIN_LITERAL_PREFIX_CHARS;

/// Extract literal prefixes from a regex pattern for Aho-Corasick.
/// Handles simple literals and top-level groups like (AKIA|ASIA).
pub fn extract_literal_prefixes(pattern: &str) -> Vec<String> {
    // Strip leading inline flags like (?i), (?m), (?s), (?x), (?im), etc.
    // These set regex modes but don't consume input.
    let pattern = strip_leading_inline_flags(pattern);

    if pattern.starts_with('(') && pattern.contains('|') {
        // Handle (A|B|C)
        let mut depth = 0;
        let mut end_idx = None;
        for (i, ch) in pattern.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end_idx = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }

        if let Some(end) = end_idx {
            let mut inner = &pattern[1..end];
            // Strip non-capturing group prefix (?:, (?i:, (?im:, etc.)
            if inner.starts_with("?:") {
                inner = &inner[2..];
            } else if inner.starts_with("?i:")
                || inner.starts_with("?m:")
                || inner.starts_with("?s:")
            {
                inner = &inner[3..];
            } else if inner.starts_with("?im:")
                || inner.starts_with("?is:")
                || inner.starts_with("?ms:")
            {
                inner = &inner[4..];
            }
            // Split by |, but only at depth 0
            let mut parts = Vec::new();
            let mut start = 0;
            let mut d = 0;
            for (i, ch) in inner.char_indices() {
                match ch {
                    '(' => d += 1,
                    ')' => d -= 1,
                    '|' if d == 0 => {
                        parts.push(&inner[start..i]);
                        start = i + 1;
                    }
                    _ => {}
                }
            }
            parts.push(&inner[start..]);

            let mut results = Vec::new();
            for part in parts {
                if let Some(p) = extract_literal_prefix(part) {
                    results.push(p);
                }
            }
            if !results.is_empty() {
                return results;
            }
        }
    }

    // Default: try to extract a single prefix from the start
    extract_literal_prefix(pattern).into_iter().collect()
}

/// Strip leading inline flags like `(?i)`, `(?m)`, `(?ims)` from a regex.
/// These set modes for the rest of the pattern but don't produce a group.
fn strip_leading_inline_flags(pattern: &str) -> &str {
    if !pattern.starts_with("(?") {
        return pattern;
    }
    // (?i), (?m), (?s), (?x), (?im), (?ims), (?imsx) etc. — flags only, no ':'
    let bytes = pattern.as_bytes();
    if bytes.len() < 4 || bytes[0] != b'(' || bytes[1] != b'?' {
        return pattern;
    }
    let mut i = 2;
    while i < bytes.len() && matches!(bytes[i], b'i' | b'm' | b's' | b'x' | b'u' | b'U') {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b')' {
        // (?flags) — strip the entire inline flag group
        &pattern[i + 1..]
    } else {
        pattern
    }
}

pub fn extract_literal_prefix(pattern: &str) -> Option<String> {
    let mut prefix = String::new();
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                let Some(next) = chars.next() else {
                    break;
                };
                if is_escaped_literal(next) {
                    prefix.push(next);
                } else {
                    break;
                }
            }
            '[' | '.' | '*' | '+' | '?' | '{' | '|' | '^' | '$' => break,
            '(' => {
                // Mid-pattern alternation: try to extend the prefix with
                // the group's alternatives. This turns "secret_(key|token)"
                // into prefix "secret_key" (the longest common prefix after
                // expanding alternatives). If the group has no pipe, continue
                // extracting the literal inside it.
                let group_start = chars.clone().collect::<String>();
                if let Some(alternatives) = extract_group_alternatives(&group_start) {
                    // Find the longest common prefix of all alternatives
                    if let Some(first) = alternatives.first() {
                        let common: String = first
                            .chars()
                            .enumerate()
                            .take_while(|(i, c)| {
                                alternatives
                                    .iter()
                                    .all(|alt| alt.chars().nth(*i) == Some(*c))
                            })
                            .map(|(_, c)| c)
                            .collect();
                        if !common.is_empty() {
                            prefix.push_str(&common);
                        }
                    }
                }
                break;
            }
            _ => {
                prefix.push(ch);
            }
        }
    }
    if prefix.len() >= MIN_LITERAL_PREFIX_CHARS {
        Some(prefix)
    } else {
        None
    }
}

/// Extract literal alternatives from a group at the start of a string.
/// Input: "key|token)rest..." → Some(["key", "token"])
/// Returns None if the group contains regex metacharacters.
fn extract_group_alternatives(s: &str) -> Option<Vec<String>> {
    // Strip optional non-capturing prefix
    let inner = s
        .strip_prefix("?:")
        .or_else(|| s.strip_prefix("?i:"))
        .or_else(|| s.strip_prefix("?im:"))
        .unwrap_or(s);

    let mut depth = 0i32;
    let mut end = None;
    for (i, ch) in inner.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                if depth == 0 {
                    end = Some(i);
                    break;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    let end = end?;
    let group_content = &inner[..end];

    // Split by | at depth 0
    let mut parts = Vec::new();
    let mut start = 0;
    let mut d = 0i32;
    for (i, ch) in group_content.char_indices() {
        match ch {
            '(' => d += 1,
            ')' => d -= 1,
            '|' if d == 0 => {
                parts.push(&group_content[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&group_content[start..]);

    // Extract literal prefix from each alternative
    let literals: Vec<String> = parts
        .iter()
        .filter_map(|part| {
            let mut lit = String::new();
            for ch in part.chars() {
                match ch {
                    'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | '.' | ':' | '=' | ' ' => {
                        lit.push(ch);
                    }
                    '\\' => break, // escaped char — stop
                    _ => break,    // metachar — stop
                }
            }
            if lit.is_empty() {
                None
            } else {
                Some(lit)
            }
        })
        .collect();

    if literals.len() == parts.len() && !literals.is_empty() {
        Some(literals)
    } else {
        None
    }
}

pub fn is_escaped_literal(ch: char) -> bool {
    matches!(
        ch,
        '[' | ']' | '(' | ')' | '.' | '*' | '+' | '?' | '{' | '}' | '\\' | '|' | '^' | '$'
    )
}
