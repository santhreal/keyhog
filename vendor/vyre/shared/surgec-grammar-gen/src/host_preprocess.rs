//! Host-side C preprocessor **subset** for P3: line splicing, comment
//! stripping, and `#if 0` / `#endif` removal. Full macro expansion and
//! include resolution are intentionally **out of scope** here; see
//! `docs/parsing-and-frontends.md` (GPU cpp non-scope).

/// Apply a conservative host preprocess pass suitable before lexing
/// experiments on disk snippets.
///
/// Order: line splice (`\\\n`) → strip `/* */` → strip `//` → fold
/// `#if 0` … `#endif` blocks (no expression evaluation).
#[must_use]
pub fn preprocess_c_host(input: &str) -> String {
    let spliced = splice_lines(input);
    let no_block = strip_block_comments(&spliced);
    let no_line = strip_line_comments(&no_block);
    strip_if_zero_blocks(&no_line)
}

fn splice_lines(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('\r') => {
                    chars.next();
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                    out.push(' ');
                    continue;
                }
                Some('\n') => {
                    chars.next();
                    out.push(' ');
                    continue;
                }
                _ => {}
            }
        }
        out.push(c);
    }
    out
}

fn strip_block_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find("/*") {
        out.push_str(&rest[..pos]);
        rest = &rest[pos + 2..];
        match rest.find("*/") {
            Some(end) => {
                rest = &rest[end + 2..];
                out.push(' ');
            }
            None => break,
        }
    }
    out.push_str(rest);
    out
}

fn strip_line_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for line in input.lines() {
        let mut cut = None;
        let b = line.as_bytes();
        let mut j = 0usize;
        while j + 1 < b.len() {
            if b[j] == b'/' && b[j + 1] == b'/' {
                cut = Some(j);
                break;
            }
            j += 1;
        }
        match cut {
            Some(idx) => {
                out.push_str(&line[..idx]);
                out.push('\n');
            }
            None => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    if !input.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    out
}

fn strip_if_zero_blocks(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let lines: Vec<&str> = input.lines().collect();
    let mut i = 0usize;
    while i < lines.len() {
        let t = lines[i].trim_start();
        let is_if_zero = {
            let mut it = t.split_whitespace();
            it.next() == Some("#if") && it.next() == Some("0")
        };
        if is_if_zero {
            let mut depth = 1usize;
            i += 1;
            while i < lines.len() && depth > 0 {
                let u = lines[i].trim_start();
                let mut wit = u.split_whitespace();
                let head = wit.next();
                if head == Some("#if") {
                    depth += 1;
                } else if head == Some("#endif") {
                    depth -= 1;
                }
                i += 1;
            }
            continue;
        }
        out.push_str(lines[i]);
        out.push('\n');
        i += 1;
    }
    if !input.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splices_backslash_newline() {
        assert_eq!(preprocess_c_host("a\\\nb"), "a b".to_string());
    }

    #[test]
    fn strips_block_comment() {
        assert_eq!(preprocess_c_host("x/*c*/y"), "x y".to_string());
    }

    #[test]
    fn strips_line_comment() {
        assert_eq!(preprocess_c_host("ok //x"), "ok ".to_string());
    }

    #[test]
    fn strips_if_zero() {
        let s = preprocess_c_host("#if 0\nBAD\n#endif\nOK");
        assert!(!s.contains("BAD"));
        assert!(s.contains("OK"));
    }
}
