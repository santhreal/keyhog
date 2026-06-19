use crate::types::MIN_LITERAL_PREFIX_CHARS;

/// Extract literal prefixes from a regex pattern for Aho-Corasick.
/// Handles simple literals and top-level groups like (AKIA|ASIA).
pub(crate) fn extract_literal_prefixes(pattern: &str) -> Vec<String> {
    // Strip leading inline flags like (?i), (?m), (?s), (?x), (?im), etc.
    // These set regex modes but don't consume input.
    let pattern = strip_leading_inline_flags(pattern);

    // Boundary-guard idiom: `(?:^|[^...])(LITERAL...)`. Secret detectors
    // prefix the real token with a zero-/one-width boundary guard so the
    // match requires start-of-line or a non-word char before the token
    // (helicone `(?:^|[^A-Za-z0-9_])(sk-…{20,})`, deepnote `(…)(dn_…{20,})`).
    // The guard carries no literal, so prefix extraction returned nothing
    // and the detector fell to the keyword-gated phase-2 lane - where a bare
    // token positive (`sk-…`, `dn_…`) whose only ≥4-char keyword is absent
    // never fired (contracts_runner: helicone / deepnote MISSED). Strip the
    // guard and extract the prefix from what follows. The full regex (guard
    // included) still confirms at extraction time, so AC only GAINS the
    // trigger literal - precision is held by the `{20,}` body, and routing
    // via the full-regex AC path is strictly more precise than the keyword
    // phase-2 keyword route this replaces.
    if let Some(rest) = strip_leading_boundary_guard(pattern) {
        let inner = extract_literal_prefixes(rest);
        if !inner.is_empty() {
            return inner;
        }
    }

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

/// If `pattern` opens with a non-capturing boundary-guard group whose every
/// alternative is a zero-/one-width boundary token (`^`, `$`, `\b`, `\B`,
/// `\w`, `\W`, or a `[...]` char class), return the slice AFTER that group.
/// Used to see past the `(?:^|[^A-Za-z0-9_])` prefix idiom so the real
/// literal token in the following group can be pulled into the AC set.
/// Returns `None` if the leading group is anything else (so a normal
/// alternation like `(AKIA|ASIA)` is untouched).
pub(crate) fn strip_leading_boundary_guard(pattern: &str) -> Option<&str> {
    let body = pattern.strip_prefix("(?:")?;
    // Find the matching ')' for this group at depth 0, skipping escapes
    // and the interior of `[...]` classes (a `]`-less `)` inside a class
    // must not close the group).
    let bytes = body.as_bytes();
    let mut depth = 0i32;
    let mut in_class = false;
    let mut i = 0;
    let mut end = None;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 1, // skip the escaped byte
            b'[' if !in_class => in_class = true,
            b']' if in_class => in_class = false,
            b'(' if !in_class => depth += 1,
            b')' if !in_class => {
                if depth == 0 {
                    end = Some(i);
                    break;
                }
                depth -= 1;
            }
            _ => {}
        }
        i += 1;
    }
    let end = end?;
    let group = &body[..end];
    let rest = &body[end + 1..];
    if group.is_empty() || rest.is_empty() {
        return None;
    }
    // Every top-level `|` alternative must be a boundary token. Split at
    // depth 0 and outside char classes so a `|` inside `[..|..]` doesn't
    // mis-split (the all-boundary check below would reject it anyway).
    let mut alts = Vec::new();
    let mut start = 0;
    let mut d = 0i32;
    let mut cls = false;
    for (j, ch) in group.char_indices() {
        match ch {
            '[' if !cls => cls = true,
            ']' if cls => cls = false,
            '(' if !cls => d += 1,
            ')' if !cls => d -= 1,
            '|' if d == 0 && !cls => {
                alts.push(&group[start..j]);
                start = j + 1;
            }
            _ => {}
        }
    }
    alts.push(&group[start..]);
    let all_boundary = alts.iter().all(|a| {
        let a = a.trim();
        matches!(
            a,
            "^" | "$"
                | r"\b"
                | r"\B"
                | r"\w"
                | r"\W"
                | r"\s"
                | r"\S"
                | r"\d"
                | r"\D"
                | r"\A"
                | r"\z"
        ) || (a.starts_with('[') && a.ends_with(']') && a.len() >= 3)
    });
    if all_boundary {
        Some(rest)
    } else {
        None
    }
}

/// Strip leading inline flags like `(?i)`, `(?m)`, `(?ims)` from a regex.
/// These set modes for the rest of the pattern but don't produce a group.
pub(crate) fn strip_leading_inline_flags(pattern: &str) -> &str {
    if !pattern.starts_with("(?") {
        return pattern;
    }
    // (?i), (?m), (?s), (?x), (?im), (?ims), (?imsx) etc. - flags only, no ':'.
    // Also the negative form (?-i), (?im-sx): the `-` toggles following flags
    // off (keyhog uses (?-i) to make a pattern case-sensitive). A trailing `:`
    // means a scoped group `(?-i:...)`, not a leading directive - left intact.
    let bytes = pattern.as_bytes();
    if bytes.len() < 4 || bytes[0] != b'(' || bytes[1] != b'?' {
        return pattern;
    }
    let mut i = 2;
    while i < bytes.len() && matches!(bytes[i], b'i' | b'm' | b's' | b'x' | b'u' | b'U' | b'-') {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b')' {
        // (?flags) - strip the entire inline flag group
        &pattern[i + 1..]
    } else {
        pattern
    }
}

pub(crate) fn extract_literal_prefix(pattern: &str) -> Option<String> {
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
        .unwrap_or(s); // LAW10: no non-capturing prefix present => use the group source unchanged (intended), recall-safe

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
                    '\\' => break, // escaped char - stop
                    _ => break,    // metachar - stop
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

pub(crate) fn is_escaped_literal(ch: char) -> bool {
    matches!(
        ch,
        '[' | ']' | '(' | ')' | '.' | '*' | '+' | '?' | '{' | '}' | '\\' | '|' | '^' | '$'
    )
}

/// Minimum length for an inner literal to be eligible for the AC prefilter.
///
/// Inner literals are pulled from anywhere in the regex (after a leading
/// character class, between groups, etc.) rather than just the prefix, so
/// they're typically less specific than a prefix-anchored literal. We
/// require ≥ 4 chars to keep the AC working set tight and avoid spurious
/// chunks getting promoted to regex confirmation. The 3-char prefix
/// threshold remains for `extract_literal_prefix` because a 3-char prefix
/// is positionally anchored and far more discriminative.
pub(crate) const MIN_INNER_LITERAL_CHARS: usize = 4;

/// Extract literal substrings from anywhere in a regex pattern (not just
/// the start), suitable as Aho-Corasick prefilter triggers for phase-2 patterns
/// whose start is a character class.
///
/// Walks the parsed regex AST and collects every contiguous run of
/// `Literal` nodes inside a `Concat`. Alternation branches are walked
/// recursively (each branch's literals are independent candidates).
/// Repetitions and assertions break the run conservatively: even though
/// `\babc\b` always contains "abc", we also allow that the surrounding
/// regex might never match, in which case we'd be promoting chunks for
/// nothing - the regex confirmation still has to succeed, but the AC's
/// job is to skip work, not generate it.
///
/// Examples:
///   `[a-zA-Z0-9]{20}_AKIA[A-Z0-9]{16}` → `["_AKIA"]`
///   `(?:secret|api_key)\s*=\s*[a-z0-9]{32}` → `["secret", "api_key"]`
///   `[a-f0-9]{32}` → `[]`
///   `wx[a-f0-9]{16}` → `[]` (the `wx` prefix is below the 4-char floor)
pub(crate) fn extract_inner_literals(pattern: &str) -> Vec<String> {
    use regex_syntax::ast::parse::Parser;
    let Ok(ast) = Parser::new().parse(pattern) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    walk_ast(&ast, &mut out);
    out.retain(|s| s.len() >= MIN_INNER_LITERAL_CHARS);
    // Dedup while preserving order - alternation branches commonly produce
    // duplicates when patterns share prefixes (e.g. `(KEY|key)` lowered to
    // canonical literals).
    let mut seen = std::collections::HashSet::new();
    out.retain(|s| seen.insert(s.clone()));
    out
}

fn walk_ast(ast: &regex_syntax::ast::Ast, out: &mut Vec<String>) {
    use regex_syntax::ast::Ast;
    match ast {
        Ast::Concat(concat) => {
            // Collect runs of consecutive `Literal` nodes; flush a run when
            // a non-literal node breaks it. The `Literal::c` field is the
            // character - for `\.` it's `.`, for `\\` it's `\`, etc.
            let mut run = String::new();
            for inner in concat.asts.iter() {
                match inner {
                    Ast::Literal(lit) => run.push(lit.c),
                    _ => {
                        if run.len() >= MIN_INNER_LITERAL_CHARS {
                            out.push(std::mem::take(&mut run));
                        } else {
                            run.clear();
                        }
                        walk_ast(inner, out);
                    }
                }
            }
            if run.len() >= MIN_INNER_LITERAL_CHARS {
                out.push(run);
            }
        }
        Ast::Group(group) => walk_ast(&group.ast, out),
        Ast::Alternation(alt) => {
            for branch in alt.asts.iter() {
                walk_ast(branch, out);
            }
        }
        // Single literal at the top level - wrap into a one-char run; the
        // caller's filter rejects it for length but the case is rare anyway.
        Ast::Literal(lit) => {
            let s = lit.c.to_string();
            if s.len() >= MIN_INNER_LITERAL_CHARS {
                out.push(s);
            }
        }
        // Repetition operands could in principle contribute a literal when
        // `min >= 1`, but the operand's literals would also need to be
        // resolved through the operand's own AST shape. Keeping this
        // conservative dodges a class of "we extracted `a` from `a+`,
        // promoted every chunk with an `a` to regex confirmation" gotchas.
        Ast::Repetition(_)
        | Ast::ClassUnicode(_)
        | Ast::ClassPerl(_)
        | Ast::ClassBracketed(_)
        | Ast::Dot(_)
        | Ast::Empty(_)
        | Ast::Flags(_)
        | Ast::Assertion(_) => {}
    }
}
