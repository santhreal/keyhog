//! Verify-block brace templating helpers.
//!
//! `keyhog detectors --fix-template-braces` rewrites
//! `{name}` -> `{{name}}` in `[detector.verify*]` blocks so the
//! TOML-side template engine can pick them up. Scoped to verify
//! blocks because `detector.patterns[].regex` and
//! `detector.companions[].regex` also contain braces (regex
//! quantifiers like `{4,6}`) that must NOT be rewritten.

/// Rewrite single-brace `{name}` references to `{{name}}` inside lines
/// that belong to a `[detector.verify*]` block. Returns the new content
/// and the number of rewrites performed.
///
/// Scoped to verify blocks because that's the only place the templating
/// engine runs - `detector.patterns[].regex` and
/// `detector.companions[].regex` also contain braces (regex quantifiers
/// like `{4,6}`) and must not be rewritten. The interpolator is
/// tolerant of `{{var}}` outside verify blocks too, but applying the
/// rewrite there would risk corrupting regex quantifiers.
pub(super) fn fix_single_brace_in_verify_blocks(toml_text: &str) -> (String, usize) {
    let mut out = String::with_capacity(toml_text.len());
    let mut in_verify = false;
    let mut total = 0usize;
    for line in toml_text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix('[') {
            let header = rest.trim_end_matches(['\r', ' ', '\t']);
            in_verify = header.starts_with("detector.verify")
                || header.starts_with("[detector.verify")
                || header == "detector.verify]"
                || header == "[detector.verify]]";
            if !in_verify {
                let stripped = header.trim_matches(['[', ']'].as_ref());
                in_verify = stripped.starts_with("detector.verify");
            }
        }
        if in_verify {
            let (rewritten, count) = rewrite_braces_in_string_literals(line);
            total += count;
            out.push_str(&rewritten);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    if !toml_text.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    (out, total)
}

/// Rewrite `{name}` -> `{{name}}` ONLY inside double-quoted (`"..."`)
/// or single-quoted (`'...'`) string literals on a TOML line. Skips
/// unquoted regions (so regex quantifiers in unkeyed positions don't
/// get touched) and skips already-doubled `{{var}}` patterns.
pub(super) fn rewrite_braces_in_string_literals(line: &str) -> (String, usize) {
    // Operate on `char`s, not bytes: the structural tokens we match (quotes,
    // backslash, braces, identifier chars) are all ASCII, but a verify-block
    // string value may carry non-ASCII UTF-8 (`body = "héllo {name}"`). The
    // previous byte-walk did `byte as char`, which reinterprets each UTF-8
    // continuation byte as a separate Latin-1 scalar and corrupts the value into
    // mojibake. Char-indexing keeps multi-byte scalars intact; on pure-ASCII
    // input the output is byte-identical to the old path.
    let chars: Vec<char> = line.chars().collect();
    let mut out = String::with_capacity(line.len());
    let mut count = 0usize;
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '"' || ch == '\'' {
            let quote = ch;
            out.push(quote);
            let mut j = i + 1;
            let mut literal = String::new();
            while j < chars.len() {
                let c = chars[j];
                if quote == '"' && c == '\\' && j + 1 < chars.len() {
                    literal.push(c);
                    literal.push(chars[j + 1]);
                    j += 2;
                    continue;
                }
                if c == quote {
                    break;
                }
                literal.push(c);
                j += 1;
            }
            let (rewritten_literal, c) = rewrite_braces(&literal);
            count += c;
            out.push_str(&rewritten_literal);
            if j < chars.len() {
                out.push(quote);
                i = j + 1;
            } else {
                i = j;
            }
        } else {
            out.push(ch);
            i += 1;
        }
    }
    (out, count)
}

/// Replace `{name}` with `{{name}}` where `name` matches
/// `[A-Za-z_][A-Za-z0-9_.]*`. Leaves already-doubled `{{name}}` alone
/// and ignores braces that don't open an identifier.
pub(super) fn rewrite_braces(s: &str) -> (String, usize) {
    // Char-indexed for the same UTF-8 reason as `rewrite_braces_in_string_literals`
    // (a literal may contain non-ASCII); the identifier charset `[A-Za-z0-9_.]`
    // is ASCII, so the matched name still slices correctly. Byte-identical to the
    // old byte-walk on pure-ASCII input.
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut count = 0usize;
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '{' {
            if i + 1 < chars.len() && chars[i + 1] == '{' {
                out.push('{');
                out.push('{');
                i += 2;
                continue;
            }
            let start = i + 1;
            if start < chars.len() && (chars[start].is_ascii_alphabetic() || chars[start] == '_') {
                let mut end = start + 1;
                while end < chars.len()
                    && (chars[end].is_ascii_alphanumeric()
                        || chars[end] == '_'
                        || chars[end] == '.')
                {
                    end += 1;
                }
                if end < chars.len() && chars[end] == '}' {
                    out.push_str("{{");
                    out.extend(chars[start..end].iter());
                    out.push_str("}}");
                    count += 1;
                    i = end + 1;
                    continue;
                }
            }
            out.push('{');
            i += 1;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    (out, count)
}
