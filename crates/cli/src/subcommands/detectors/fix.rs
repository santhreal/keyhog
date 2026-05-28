use anyhow::{Context, Result};
use std::path::{Path, PathBuf};


pub(super) fn list_toml_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let read =
        std::fs::read_dir(dir).with_context(|| format!("reading directory {}", dir.display()))?;
    for entry in read {
        let entry = entry.with_context(|| format!("reading entry under {}", dir.display()))?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("toml") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Atomic file replace: write the new content into a tempfile in the same
/// directory, fsync, then rename onto the target. A crash mid-write
/// leaves the original file intact rather than truncating it.
pub(super) fn atomic_write(path: &Path, content: &str) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating tempfile in {}", parent.display()))?;
    {
        use std::io::Write;
        let mut handle = tmp.as_file();
        handle.write_all(content.as_bytes())?;
        handle.flush()?;
        handle.sync_all()?;
    }
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Rewrite single-brace `{name}` references to `{{name}}` inside lines
/// that belong to a `[detector.verify*]` block. Returns the new content
/// and the number of rewrites performed.
///
/// Scoped to verify blocks because that's the only place the templating
/// engine runs — `detector.patterns[].regex` and `detector.companions[].regex`
/// also contain braces (regex quantifiers like `{4,6}`) and must not be
/// rewritten. The interpolator is tolerant of `{{var}}` outside verify
/// blocks too, but applying the rewrite there would risk corrupting
/// regex quantifiers.
pub fn fix_single_brace_in_verify_blocks(toml_text: &str) -> (String, usize) {
    let mut out = String::with_capacity(toml_text.len());
    let mut in_verify = false;
    let mut total = 0usize;
    for line in toml_text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix('[') {
            let header = rest.trim_end_matches(['\r', ' ', '\t']);
            // Header forms: `[detector.verify]`, `[[detector.verify.steps]]`,
            // `[detector.verify.oob]`, etc. Anything else flips us out.
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
    // Preserve absence of trailing newline if the original lacked one.
    if !toml_text.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    (out, total)
}

/// Rewrite `{name}` → `{{name}}` ONLY inside double-quoted (`"..."`) or
/// single-quoted (`'...'`) string literals on a TOML line. Skips
/// unquoted regions (so regex quantifiers in unkeyed positions don't
/// get touched) and skips already-doubled `{{var}}` patterns.
#[doc(hidden)]
pub fn rewrite_braces_in_string_literals(line: &str) -> (String, usize) {
    let mut out = String::with_capacity(line.len());
    let mut count = 0usize;
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' || b == b'\'' {
            // Find matching quote (TOML doesn't support escapes inside
            // single-quoted literal strings; double-quoted strings allow
            // `\"`, which we honour).
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
#[doc(hidden)]
pub fn rewrite_braces(s: &str) -> (String, usize) {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut count = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            // Already `{{`? Skip the run of opening braces unchanged.
            if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                out.push('{');
                out.push('{');
                i += 2;
                continue;
            }
            // Try to parse `{ident}` from here.
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
                    // Successful `{ident}` capture — promote to `{{ident}}`.
                    out.push_str("{{");
                    out.push_str(&s[start..end]);
                    out.push_str("}}");
                    count += 1;
                    i = end + 1;
                    continue;
                }
            }
            // Not a templated identifier — pass through.
            out.push('{');
            i += 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    (out, count)
}
