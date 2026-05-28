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
    let mut out = String::with_capacity(line.len());
    let mut count = 0usize;
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' || b == b'\'' {
            let quote = b;
            out.push(quote as char);
            let mut j = i + 1;
            let mut literal = String::new();
            while j < bytes.len() {
                let c = bytes[j];
                if quote == b'"' && c == b'\\' && j + 1 < bytes.len() {
                    literal.push(c as char);
                    literal.push(bytes[j + 1] as char);
                    j += 2;
                    continue;
                }
                if c == quote {
                    break;
                }
                literal.push(c as char);
                j += 1;
            }
            let (rewritten_literal, c) = rewrite_braces(&literal);
            count += c;
            out.push_str(&rewritten_literal);
            if j < bytes.len() {
                out.push(quote as char);
                i = j + 1;
            } else {
                i = j;
            }
        } else {
            out.push(b as char);
            i += 1;
        }
    }
    (out, count)
}

/// Replace `{name}` with `{{name}}` where `name` matches
/// `[A-Za-z_][A-Za-z0-9_.]*`. Leaves already-doubled `{{name}}` alone
/// and ignores braces that don't open an identifier.
pub(super) fn rewrite_braces(s: &str) -> (String, usize) {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut count = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                out.push('{');
                out.push('{');
                i += 2;
                continue;
            }
            let start = i + 1;
            if start < bytes.len() && (bytes[start].is_ascii_alphabetic() || bytes[start] == b'_') {
                let mut end = start + 1;
                while end < bytes.len()
                    && (bytes[end].is_ascii_alphanumeric()
                        || bytes[end] == b'_'
                        || bytes[end] == b'.')
                {
                    end += 1;
                }
                if end < bytes.len() && bytes[end] == b'}' {
                    out.push_str("{{");
                    out.push_str(&s[start..end]);
                    out.push_str("}}");
                    count += 1;
                    i = end + 1;
                    continue;
                }
            }
            out.push('{');
            i += 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    (out, count)
}
