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
