use crate::types::MIN_LITERAL_PREFIX_CHARS;

/// Extract literal prefixes from a regex pattern for Aho-Corasick.
/// Handles simple literals and top-level groups like (AKIA|ASIA).
pub(crate) fn extract_literal_prefixes(pattern: &str) -> Vec<String> {
    // Strip leading inline flags like (?i), (?m), (?s), (?x), (?im), etc.
    // These set regex modes but don't consume input.
    let pattern = strip_leading_inline_flags(pattern);

    // Strip leading zero-width assertions (`\b`, `\B`, `\A`, `^`). They anchor
    // the match position but consume no input, so the literal that follows
    // (`\bser\.` → `ser\.`) is the real prefix. Without this the leading `\b`
    // broke extraction at the first byte and the detector carried no AC trigger
    // / literal-prefix anchor (contracts_runner: flagsmith MISSED).
    let pattern = strip_leading_zero_width_assertions(pattern);

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
            // Strip the non-capturing / inline-flag group prefix (`?:`, `?i:`,
            // `?im:`, …) through the single shared owner `strip_group_prefix`,
            // instead of a second hand-maintained copy of the same flag-form set.
            // Byte-identical to the old inline chain (same forms, same order), and
            // now the recognised-flag set has ONE definitional home — so extending
            // it (e.g. the missing 3-flag `?ims:` form) is a one-place change that
            // this routing path and `extract_group_alternatives`/`expand_*` all
            // pick up together instead of drifting.
            let inner = strip_group_prefix(&pattern[1..end]);
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
                } else {
                    // Partial alternation coverage is unsafe: AC routing would
                    // admit only the prefixed branches and make the others dead.
                    results.clear();
                    break;
                }
            }
            if !results.is_empty() {
                return results;
            }
        }
    }

    // A clean leading literal prefix (`AKIA…`, `cs_…`) is the common case.
    if let Some(p) = extract_literal_prefix(pattern) {
        return vec![p];
    }

    // Fallback: a leading literal run interrupted by a small, fully-enumerable
    // character class (`dd[npc]_…`). `extract_literal_prefix` stops at the `[`
    // carrying only a sub-floor stub (`dd`), so the detector would route on its
    // keyword lane alone and a bare-token positive scored below the confidence
    // floor (contracts_runner: deno-kv MISSED). Expanding the class into one
    // concrete prefix per member (`ddn_`, `ddp_`, `ddc_`) is the exact analogue
    // of expanding the `(n|p|c)` alternation above, so each branch earns its AC
    // trigger + literal-prefix anchor; the full regex still confirms.
    if let Some(expanded) = expand_leading_charclass_prefixes(pattern) {
        return expanded;
    }

    // Fallback: a leading alternation of SHORT pure literals that only clear the
    // floor once extended with the literal following the group (`(?:pk|sk)\.` →
    // `pk.`/`sk.`). The per-branch alternation path above expands `pk`/`sk` but
    // each is sub-floor on its own, so it declined; carrying the trailing `\.`
    // discriminator onto every branch recovers them (contracts_runner:
    // locationiq MISSED).
    if let Some(expanded) = expand_leading_literal_alternation_with_tail(pattern) {
        return expanded;
    }

    Vec::new()
}

/// The leading run of literal characters of `s`, unescaping simple escaped
/// literals (`\.` → `.`, `\-` → `-`) and stopping at the first metacharacter,
/// quantifier, group, or class. Unlike [`extract_literal_prefix`] this applies
/// no length floor and does not expand groups: it is the raw literal head used
/// to extend an expanded prefix past the construct that produced it (a char
/// class or a literal alternation) to its next break. A bare `.` is the
/// any-char metacharacter and stops the run, exactly as `extract_literal_prefix`
/// treats it; only the escaped `\.` contributes a literal dot.
pub(crate) fn leading_literal_run(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => match chars.next() {
                Some(next) if is_escaped_literal(next) => out.push(next),
                _ => break,
            },
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | ':' | '=' => out.push(ch),
            _ => break,
        }
    }
    out
}

/// Expand a leading alternation whose every branch is a pure literal, extending
/// each branch with the literal that follows the group.
///
/// `(?:pk|sk)\.[a-f0-9]{32,}` splits into `pk`/`sk` — both below the 3-char
/// floor, so the per-branch alternation path declines and the detector carries
/// no prefix anchor (contracts_runner: locationiq MISSED). The literal `\.`
/// after the group applies to EVERY branch, so carrying it on yields the real
/// discriminating prefixes `pk.`/`sk.`.
///
/// Conservative by construction: the leading group must be a top-level
/// alternation of pure literal runs (a structured branch — nested group, class,
/// quantifier — is declined, since the post-group tail would not abut its
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

/// Upper bound on how many members a leading character class may have before
/// `expand_leading_charclass_prefixes` declines to enumerate it. A genuine
/// service-prefix discriminator (`dd[npc]_`, `sk[_-]live`) has a handful of
/// members; a wide class (`[a-z]` after `-` expansion, `[A-Za-z0-9]`) is a body
/// matcher, not a prefix, and enumerating it would flood the AC set.
pub(crate) const MAX_CHARCLASS_PREFIX_EXPANSION: usize = 8;

/// Expand a leading literal run interrupted by a SMALL, fully-enumerable
/// character class into one concrete literal prefix per class member.
///
/// `dd[npc]_[a-f0-9]{64}` carries no extractable prefix — `extract_literal_prefix`
/// stops at `[` with only `dd` (below the 3-char floor) — even though every
/// concrete branch begins with a perfectly good literal: `ddn_`, `ddp_`,
/// `ddc_`. A character class whose members are all single literal characters is
/// semantically an alternation of those characters, so enumerating it is the
/// exact analogue of the `(n|p|c)` alternation the plural extractor already
/// expands. Each produced prefix is still confirmed by the full regex, so AC
/// routing only gains triggers and precision stays held by the body matcher.
///
/// Conservative by construction:
///   * the leading run before `[` must be plain literals (no other metachar);
///   * the class must be a bare enumeration of single literal chars — no
///     negation (`[^…]`), no ranges (`[a-f]`), no POSIX/Perl classes;
///   * cardinality ≤ [`MAX_CHARCLASS_PREFIX_EXPANSION`]; and
///   * EVERY member must yield a prefix ≥ [`MIN_LITERAL_PREFIX_CHARS`] — partial
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
                    // `\d`, `\w`, … — not a plain literal head.
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

/// If `pattern` opens with a non-capturing boundary-guard group whose every
/// alternative is a zero-/one-width boundary token (`^`, `$`, `\b`, `\B`,
/// `\w`, `\W`, or a `[...]` char class), return the slice AFTER that group.
/// Used to see past the `(?:^|[^A-Za-z0-9_])` prefix idiom so the real
/// literal token in the following group can be pulled into the AC set.
/// Returns `None` if the leading group is anything else (so a normal
/// alternation like `(AKIA|ASIA)` is untouched).
pub(crate) fn strip_leading_boundary_guard(pattern: &str) -> Option<&str> {
    split_leading_boundary_guard(pattern).map(|(_, rest)| rest)
}

pub(crate) fn split_leading_boundary_guard(pattern: &str) -> Option<(&str, &str)> {
    let body = pattern.strip_prefix("(?:")?;
    // Find the matching ')' for this group at depth 0, skipping escapes
    // and the interior of `[...]` classes (a `]`-less `)` inside a class
    // must not close the group).
    let bytes = body.as_bytes();
    let mut depth = 0i32;
    let mut in_class = false;
    let mut escaped = false;
    let mut i = 0;
    let mut end = None;
    while i < bytes.len() {
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        match bytes[i] {
            b'\\' => escaped = true,
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
    let guard_end = "(?:".len() + end + 1;
    let guard = &pattern[..guard_end];
    let rest = &pattern[guard_end..];
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
    let mut escaped = false;
    for (j, ch) in group.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
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
    all_boundary.then_some((guard, rest))
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

/// Strip a leading run of zero-width assertions — `^`, `\A`, `\b`, `\B` — that
/// anchor the match position but consume no input. The literal that follows
/// (`\bser\.` → `ser\.`, `^AKIA…` → `AKIA…`) is the detector's real prefix, so
/// without this the leading assertion broke prefix extraction at the first byte
/// and the detector carried no AC trigger / literal-prefix anchor. Idempotent
/// and order-free across the four forms; anything else is left untouched.
pub(crate) fn strip_leading_zero_width_assertions(pattern: &str) -> &str {
    let mut p = pattern;
    loop {
        let next = p
            .strip_prefix('^')
            .or_else(|| p.strip_prefix(r"\A"))
            .or_else(|| p.strip_prefix(r"\b"))
            .or_else(|| p.strip_prefix(r"\B"));
        match next {
            Some(rest) => p = rest,
            None => return p,
        }
    }
}

pub(crate) fn extract_literal_prefix(pattern: &str) -> Option<String> {
    // Strip a leading bare inline-flag group — `(?i)`, `(?-i)`, `(?im)` — which
    // sets match modes but consumes no input, so the literal that follows
    // (`(?-i)cs_…` → `cs_…`) is reachable. This is the SAME normalization the
    // routing extractor `extract_literal_prefixes` already applies; the singular
    // form (which feeds `has_literal_prefix` → the confidence `literal_prefix`
    // weight) previously skipped it, so the 62 detectors whose regex opens with
    // `(?-i)`/`(?i)` (cloudsmith `cs_`, promptlayer `pl_`, ntfy `tk_`, …) were
    // denied their literal-prefix credit and scored below the floor. A scoped
    // group `(?-i:…)` keeps its `:` and is left intact for the main parser.
    let pattern = strip_leading_inline_flags(pattern);
    // Same idea for leading zero-width assertions (`\b`, `\B`, `\A`, `^`): they
    // anchor position but consume no input, so the literal after them is the
    // real prefix (`\bser\.` → `ser\.`). Keeps the singular form (which feeds
    // `has_literal_prefix`) in agreement with the plural routing extractor.
    let pattern = strip_leading_zero_width_assertions(pattern);
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
            '[' | '.' | '+' | '|' | '^' | '$' => break,
            '*' | '?' => {
                prefix.pop();
                break;
            }
            '{' => {
                if chars.peek() == Some(&'0') {
                    prefix.pop();
                }
                break;
            }
            '(' => {
                // Mid-pattern alternation: try to extend the prefix with
                // the group's alternatives. This turns "secret_(key|token)"
                // into prefix "secret_key" (the longest common prefix after
                // expanding alternatives). If the group has no top-level pipe,
                // extract the literal prefix inside it so captured whole-token
                // patterns like `(https?://...)` route from their earliest
                // guaranteed bytes instead of a later inner literal.
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
                } else if let Some(inner) = extract_plain_group_inner(&group_start) {
                    if let Some(inner_prefix) = extract_literal_prefix(inner) {
                        prefix.push_str(&inner_prefix);
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
fn extract_plain_group_inner(s: &str) -> Option<&str> {
    let (inner, _tail) = leading_group_parts(s)?;
    let inner = strip_group_prefix(inner);
    if has_top_level_alternation(inner) {
        return None;
    }
    Some(inner)
}

fn strip_group_prefix(s: &str) -> &str {
    s.strip_prefix("?:")
        .or_else(|| s.strip_prefix("?i:"))
        .or_else(|| s.strip_prefix("?m:"))
        .or_else(|| s.strip_prefix("?s:"))
        .or_else(|| s.strip_prefix("?im:"))
        .or_else(|| s.strip_prefix("?is:"))
        .or_else(|| s.strip_prefix("?ms:"))
        .unwrap_or(s) // LAW10: no non-capturing prefix present => use the group source unchanged (intended), recall-safe
}

fn leading_group_parts(s: &str) -> Option<(&str, &str)> {
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

fn has_top_level_alternation(s: &str) -> bool {
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

fn split_top_level_alternatives(group_content: &str) -> Vec<&str> {
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

fn literal_head(part: &str) -> Option<String> {
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

/// Minimum length of a REQUIRED literal run for it to count as a distinctive
/// inner-literal anchor. A required run this long inside a token is a service
/// signature (the terraform `.atlasv1.` infix, 9 chars) rather than incidental
/// punctuation, so a named-detector match that contains it has earned the same
/// anchor credit as a leading literal prefix.
pub(crate) const MIN_DISTINCTIVE_INFIX_CHARS: usize = 8;

/// True iff EVERY match of `pattern` necessarily contains a literal run of at
/// least `min_len` characters — a required distinctive literal such as the
/// terraform `…\.atlasv1\.…` infix, whose detector regex opens with a character
/// class (no extractable prefix) and captures the whole match (no keyword
/// group), so it earns neither existing anchor signal despite being unmistakably
/// service-specific.
///
/// Sound by construction — only literals guaranteed in every match are counted:
///   * a top-level `Concat` contributes its longest run of CONSECUTIVE literal
///     nodes;
///   * a plain/non-capturing/capturing `Group` is always entered, so it is
///     descended into; and
///   * an `Alternation` (only one branch matches), a `Repetition` (the operand
///     may repeat zero times, and even `+`/`{n,}` the run is not contiguous with
///     its neighbours here), a class, dot, or assertion contribute nothing.
/// A literal inside an optional/alternative therefore never produces a false
/// "required" claim. The walk does not multiply repeated operands, so it can
/// only UNDER-count, never over-claim.
pub(crate) fn regex_has_required_literal_run(pattern: &str, min_len: usize) -> bool {
    use regex_syntax::ast::{parse::Parser, Ast};

    fn max_required_run(ast: &Ast) -> usize {
        match ast {
            Ast::Literal(_) => 1,
            Ast::Concat(concat) => {
                let mut best = 0usize;
                let mut run = 0usize;
                for node in concat.asts.iter() {
                    if matches!(node, Ast::Literal(_)) {
                        run += 1;
                        best = best.max(run);
                    } else {
                        // A required group may carry its own internal run, but it
                        // breaks the contiguous run of its literal neighbours.
                        best = best.max(max_required_run(node));
                        run = 0;
                    }
                }
                best
            }
            Ast::Group(group) => max_required_run(&group.ast),
            // Alternation, Repetition (optional operand), classes, dot,
            // assertions, flags, empty: not a guaranteed contiguous literal run.
            _ => 0,
        }
    }

    let Ok(ast) = Parser::new().parse(pattern) else {
        return false;
    };
    max_required_run(&ast) >= min_len
}
