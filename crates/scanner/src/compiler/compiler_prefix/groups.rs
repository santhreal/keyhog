use super::inner::is_escaped_literal;
use super::leading_literal_run;
use crate::types::MIN_LITERAL_PREFIX_CHARS;

/// Upper bound on how many members a leading character class may have before
/// `expand_leading_charclass_prefixes` declines to enumerate it. A genuine
/// service-prefix discriminator (`dd[npc]_`, `sk[_-]live`) has a handful of
/// members; a wide class (`[a-z]` after `-` expansion, `[A-Za-z0-9]`) is a body
/// matcher, not a prefix, and enumerating it would flood the AC set.
pub(crate) const MAX_CHARCLASS_PREFIX_EXPANSION: usize = 8;

/// Expand a leading alternation whose every branch is a pure literal, extending
/// each branch with the literal that follows the group.
///
/// `(?:pk|sk)\.[a-f0-9]{32,}` splits into `pk`/`sk`: both below the 3-char
/// floor, so the per-branch alternation path declines and the detector carries
/// no prefix anchor (contracts_runner: locationiq MISSED). The literal `\.`
/// after the group applies to EVERY branch, so carrying it on yields the real
/// discriminating prefixes `pk.`/`sk.`.
///
/// Conservative by construction: the leading group must be a top-level
/// alternation of pure literal runs (a structured branch, nested group, class,
/// quantifier, is declined, since the post-group tail would not abut its
/// literal head), there must be a non-empty trailing literal to add, and EVERY
/// branch must clear [`MIN_LITERAL_PREFIX_CHARS`] (partial coverage refused).
pub(crate) fn expand_leading_literal_alternation_with_tail(pattern: &str) -> Option<Vec<String>> {
    let after_paren = pattern.strip_prefix('(')?;
    let (inner, tail_src) = leading_group_parts(after_paren)?;
    let inner = strip_group_prefix(inner);
    if !has_top_level_alternation(inner) {
        return None;
    }

    let tail = leading_literal_run(tail_src);
    if tail.is_empty() {
        // No trailing literal to add ⇒ nothing this fallback can recover that
        // the per-branch path did not already try.
        return None;
    }

    let parts = split_top_level_alternatives(inner);
    let mut out = Vec::with_capacity(parts.len());
    for part in &parts {
        let head = leading_literal_run(part);
        // The branch must be a PURE literal run: if the literal head does not
        // consume the whole branch, a nested construct sits between it and the
        // group close, so the tail does not abut the branch's literal.
        if head.len() != part.len() {
            return None;
        }
        let mut full = head;
        full.push_str(&tail);
        if full.len() < MIN_LITERAL_PREFIX_CHARS {
            return None;
        }
        out.push(full);
    }
    (!out.is_empty()).then_some(out)
}

/// Expand a leading literal run interrupted by a SMALL, fully-enumerable
/// semantically an alternation of those characters, so enumerating it is the
/// exact analogue of the `(n|p|c)` alternation the plural extractor already
/// expands. Each produced prefix is still confirmed by the full regex, so AC
/// routing only gains triggers and precision stays held by the body matcher.
///
/// Conservative by construction:
///   * the leading run before `[` must be plain literals (no other metachar);
///   * the class must be a bare enumeration of single literal chars, no
///     negation (`[^…]`), no ranges (`[a-f]`), no POSIX/Perl classes;
///   * cardinality ≤ [`MAX_CHARCLASS_PREFIX_EXPANSION`]; and
///   * EVERY member must yield a prefix ≥ [`MIN_LITERAL_PREFIX_CHARS`], partial
///     coverage is refused outright (an unlisted branch would be dead in AC,
///     the same hazard the alternation path guards against).
pub(crate) fn expand_leading_charclass_prefixes(pattern: &str) -> Option<Vec<String>> {
    let bytes = pattern.as_bytes();

    // 1. Plain literal head up to the first unescaped `[`.
    let mut head = String::new();
    let mut i = 0;
    loop {
        let &b = bytes.get(i)?;
        match b {
            b'[' => break,
            b'\\' => {
                let next = *bytes.get(i + 1)? as char;
                if is_escaped_literal(next) {
                    head.push(next);
                    i += 2;
                } else {
                    // `\d`, `\w`, … (not a plain literal head).
                    return None;
                }
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' => {
                head.push(b as char);
                i += 1;
            }
            // Any other metacharacter before the class means this is not the
            // `<literal-run>[<members>]` shape this fallback targets.
            _ => return None,
        }
    }

    // 2. Enumerate the class members. `i` points at `[`.
    let class_start = i + 1;
    if bytes.get(class_start) == Some(&b'^') {
        return None; // negated class is not a small enumeration
    }
    let mut members = Vec::new();
    let mut j = class_start;
    while let Some(&b) = bytes.get(j) {
        match b {
            b']' => break,
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' => {
                members.push(b as char);
                j += 1;
            }
            b'\\' => {
                let next = *bytes.get(j + 1)? as char;
                if is_escaped_literal(next) {
                    members.push(next);
                    j += 2;
                } else {
                    return None;
                }
            }
            // `-` (range), or any other class metacharacter: not a bare
            // enumeration. Decline rather than guess at the expansion.
            _ => return None,
        }
        if members.len() > MAX_CHARCLASS_PREFIX_EXPANSION {
            return None;
        }
    }
    if bytes.get(j) != Some(&b']') || members.is_empty() {
        return None; // unterminated class or empty enumeration
    }

    // 3. Literal head of what follows the class (`_` in `_[a-f0-9]{64}`), so the
    //    concrete prefix extends past the class to its next break. Uses the
    //    unescaping `leading_literal_run` so an escaped tail (`\.`) also counts.
    let tail = leading_literal_run(&pattern[j + 1..]);

    let mut out = Vec::with_capacity(members.len());
    for m in members {
        let mut prefix = head.clone();
        prefix.push(m);
        prefix.push_str(&tail);
        if prefix.len() < MIN_LITERAL_PREFIX_CHARS {
            // One sub-floor branch ⇒ refuse the whole expansion: a partial set
            // would route only the long branches and leave the short ones dead.
            return None;
        }
        out.push(prefix);
    }
    Some(out)
}
/// Extract literal alternatives from a group at the start of a string.
/// Input: "key|token)rest..." → Some(["key", "token"])
/// Returns None if the group contains regex metacharacters.
pub(super) fn extract_group_alternatives(s: &str) -> Option<Vec<String>> {
    let (inner, _tail) = leading_group_parts(s)?;
    let inner = strip_group_prefix(inner);
    if !has_top_level_alternation(inner) {
        return None;
    }

    let parts = split_top_level_alternatives(inner);
    let literals: Vec<String> = parts.iter().filter_map(|part| literal_head(part)).collect();

    if literals.len() == parts.len() && !literals.is_empty() {
        Some(literals)
    } else {
        None
    }
}

/// Extract the inner source for a leading group that does not have a top-level
/// alternation. Capturing and non-capturing groups are accepted; lookahead and
/// flag-only groups naturally return no prefix through the recursive parser.
pub(super) fn extract_plain_group_inner(s: &str) -> Option<&str> {
    let (inner, _tail) = leading_group_parts(s)?;
    let inner = strip_group_prefix(inner);
    if has_top_level_alternation(inner) {
        return None;
    }
    Some(inner)
}

pub(super) fn strip_group_prefix(s: &str) -> &str {
    s.strip_prefix("?:")
        .or_else(|| s.strip_prefix("?i:"))
        .or_else(|| s.strip_prefix("?m:"))
        .or_else(|| s.strip_prefix("?s:"))
        .or_else(|| s.strip_prefix("?im:"))
        .or_else(|| s.strip_prefix("?is:"))
        .or_else(|| s.strip_prefix("?ms:"))
        .unwrap_or(s) // LAW10: no non-capturing prefix present => use the group source unchanged (intended), recall-safe
}

pub(super) fn leading_group_parts(s: &str) -> Option<(&str, &str)> {
    let mut depth = 0i32;
    let mut end = None;
    let mut in_class = false;
    let mut escaped = false;
    for (i, ch) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if in_class {
            if ch == ']' {
                in_class = false;
            }
            continue;
        }
        if ch == '[' {
            in_class = true;
            continue;
        }
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
    Some((&s[..end], &s[end + 1..]))
}

pub(super) fn has_top_level_alternation(s: &str) -> bool {
    let mut depth = 0i32;
    let mut in_class = false;
    let mut escaped = false;
    for ch in s.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if in_class {
            if ch == ']' {
                in_class = false;
            }
            continue;
        }
        if ch == '[' {
            in_class = true;
            continue;
        }
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            '|' if depth == 0 => return true,
            _ => {}
        }
    }
    false
}

pub(super) fn split_top_level_alternatives(group_content: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut d = 0i32;
    let mut in_class = false;
    let mut escaped = false;
    for (i, ch) in group_content.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if in_class {
            if ch == ']' {
                in_class = false;
            }
            continue;
        }
        if ch == '[' {
            in_class = true;
            continue;
        }
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
    parts
}

pub(super) fn literal_head(part: &str) -> Option<String> {
    let mut lit = String::new();
    for ch in part.chars() {
        match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | '.' | ':' | '=' | ' ' => {
                lit.push(ch);
            }
            '\\' => break,
            _ => break,
        }
    }
    if lit.is_empty() {
        None
    } else {
        Some(lit)
    }
}
