//! Literal prefix extraction for Aho-Corasick prefilter triggers.
//!
//! Submodules split by responsibility:
//!   - `flags`: inline-flag and zero-width-assertion stripping
//!   - `guard`: boundary-guard group detection and stripping
//!   - `groups`: alternation and character-class prefix expansion
//!   - `inner`: detector-route auditing and required-run analysis

mod flags;
mod groups;
mod guard;
mod inner;

pub(crate) use flags::{strip_leading_inline_flags, strip_leading_zero_width_assertions};
pub(crate) use groups::{
    expand_leading_charclass_prefixes, expand_leading_literal_alternation_with_tail,
    MAX_CHARCLASS_PREFIX_EXPANSION,
};
pub(crate) use guard::{split_leading_boundary_guard, strip_leading_boundary_guard};
#[cfg(test)]
pub(crate) use inner::extract_inner_literals;
pub(crate) use inner::{
    is_escaped_literal, regex_has_required_literal_run, MIN_DISTINCTIVE_INFIX_CHARS,
    MIN_INNER_LITERAL_CHARS,
};

use crate::types::MIN_LITERAL_PREFIX_CHARS;

/// Extract literal prefixes from a regex pattern for Aho-Corasick.
/// Handles simple literals and top-level groups like (AKIA|ASIA).
pub(crate) fn extract_literal_prefixes(pattern: &str) -> Vec<String> {
    // Strip leading inline flags like (?i), (?m), (?s), (?x), (?im), etc.
    // These set regex modes but don't consume input.
    let pattern = strip_leading_inline_flags(pattern);

    // Strip leading zero-width assertions (`\b`, `\B`, `\A`, `^`). They anchor
    // the match position but consume no input, so the literal that follows
    // (`\bser\.` -> `ser\.`) is the real prefix. Without this the leading `\b`
    // broke extraction at the first byte and the detector carried no AC trigger
    // / literal-prefix anchor (contracts_runner: flagsmith MISSED).
    let pattern = strip_leading_zero_width_assertions(pattern);

    // Boundary-guard idiom: `(?:^|[^...])(LITERAL...)`. Secret detectors
    // prefix the real token with a zero-/one-width boundary guard so the
    // match requires start-of-line or a non-word char before the token
    // (helicone `(?:^|[^A-Za-z0-9_])(sk-...{20,})`, deepnote `(...)(dn_...{20,})`).
    // The guard carries no literal, so prefix extraction returned nothing
    // and the detector fell to the keyword-gated phase-2 lane - where a bare
    // token positive (`sk-...`, `dn_...`) whose only >=4-char keyword is absent
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
            // `?im:`, ...) through the single shared owner `strip_group_prefix`,
            // instead of a second hand-maintained copy of the same flag-form set.
            // Byte-identical to the old inline chain (same forms, same order), and
            // now the recognised-flag set has ONE definitional home, so extending
            // it (e.g. the missing 3-flag `?ims:` form) is a one-place change that
            // this routing path and `extract_group_alternatives`/`expand_*` all
            // pick up together instead of drifting.
            let inner = groups::strip_group_prefix(&pattern[1..end]);
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

    // A clean leading literal prefix (`AKIA...`, `cs_...`) is the common case.
    if let Some(p) = extract_literal_prefix(pattern) {
        return vec![p];
    }

    // Fallback: a leading literal run interrupted by a small, fully-enumerable
    // character class (`dd[npc]_...`). `extract_literal_prefix` stops at the `[`
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
    // floor once extended with the literal following the group (`(?:pk|sk)\.` ->
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
/// literals (`\.` -> `.`, `\-` -> `-`) and stopping at the first metacharacter,
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

pub(crate) fn extract_literal_prefix(pattern: &str) -> Option<String> {
    // Strip a leading bare inline-flag group: `(?i)`, `(?-i)`, `(?im)`: which
    // sets match modes but consumes no input, so the literal that follows
    // (`(?-i)cs_...` -> `cs_...`) is reachable. This is the SAME normalization the
    // routing extractor `extract_literal_prefixes` already applies; the singular
    // form (which feeds `has_literal_prefix` -> the confidence `literal_prefix`
    // weight) previously skipped it, so the 62 detectors whose regex opens with
    // `(?-i)`/`(?i)` (cloudsmith `cs_`, promptlayer `pl_`, ntfy `tk_`, ...) were
    // denied their literal-prefix credit and scored below the floor. A scoped
    // group `(?-i:...)` keeps its `:` and is left intact for the main parser.
    let pattern = strip_leading_inline_flags(pattern);
    // Same idea for leading zero-width assertions (`\b`, `\B`, `\A`, `^`): they
    // anchor position but consume no input, so the literal after them is the
    // real prefix (`\bser\.` -> `ser\.`). Keeps the singular form (which feeds
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
                let optional_group =
                    groups::leading_group_parts(&group_start).is_some_and(|(_, tail)| {
                        tail.starts_with('?') || tail.starts_with('*') || tail.starts_with("{0")
                    });
                if optional_group {
                    // Bytes inside an optional group are not a required prefix.
                    // Keep the literal accumulated before the group and stop.
                } else if let Some(alternatives) = groups::extract_group_alternatives(&group_start)
                {
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
                } else if let Some(inner) = groups::extract_plain_group_inner(&group_start) {
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
