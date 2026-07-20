use super::ExtractedPair;

/// Cap on how many subsequent lines an unclosed quoted value or backslash
/// continuation may swallow (KH-1432). Without a cap, a single missing closer
/// at the top of a large `.env` would pull the rest of the file into one
/// value and suppress every later KEY=VALUE pair.
const MAX_ENV_VALUE_CONTINUATION_LINES: usize = 64;

/// Parse KEY=VALUE lines from an .env file.
///
/// Quoting styles recognised:
/// - `KEY="value"` and `KEY='value'` (matching ASCII single/double quotes).
/// - `` KEY=`value` `` backtick-quoted bodies (some shells + dotenv-cli
///   accept these).
/// - Bare `KEY=value` with no quotes.
/// - Quoted multiline values (`KEY="line1\nline2"`) and backslash-continued
///   bare values (`KEY=part1\\\npart2`) (KH-1346), capped at
///   [`MAX_ENV_VALUE_CONTINUATION_LINES`] joins (KH-1432).
///
/// Inline comments are stripped on UNQUOTED values only. Sample seen in
/// `.env` files: `DB_PASS=p4ssw0rd # rotate quarterly` -> value = `p4ssw0rd`.
/// Quoted values keep `#` because the user has explicitly opted into the
/// literal string including the hash.
pub(crate) fn parse_env(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0usize;
    while i < lines.len() {
        let line_idx = i;
        let trimmed = lines[i].trim();
        i += 1;
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let after_export = strip_export_prefix(trimmed);
        let Some((key, value_start)) = after_export.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let mut value = value_start.trim().to_string();
        // Open quoted value without a closing quote on this line: keep joining
        // subsequent lines until the quote closes, EOF, or the continuation
        // cap (KH-1432). Past the cap, emit the partial value and resume
        // parsing so later keys are not swallowed.
        if let Some(quote) = open_quote_byte(&value) {
            if closing_quote_idx(&value, quote).is_none() {
                let mut joined = 0usize;
                while i < lines.len() && joined < MAX_ENV_VALUE_CONTINUATION_LINES {
                    value.push('\n');
                    value.push_str(lines[i]);
                    i += 1;
                    joined += 1;
                    if closing_quote_idx(&value, quote).is_some() {
                        break;
                    }
                }
            }
        } else {
            // Bare backslash continuations: `KEY=foo\\\nbar` → `foobar`.
            let mut joined = 0usize;
            while value.ends_with('\\')
                && !value.ends_with("\\\\")
                && i < lines.len()
                && joined < MAX_ENV_VALUE_CONTINUATION_LINES
            {
                value.pop(); // drop trailing \
                value.push_str(lines[i].trim_start());
                i += 1;
                joined += 1;
            }
        }
        let unquoted = unquote_env_value(&value);
        pairs.push(ExtractedPair {
            context: key.to_string(),
            value: unquoted,
            line: line_idx + 1,
            transport_decoded: false,
        });
    }
    pairs
}

fn open_quote_byte(s: &str) -> Option<u8> {
    let b = s.as_bytes().first().copied()?;
    matches!(b, b'"' | b'\'' | b'`').then_some(b)
}

/// Strip a leading `export` keyword (`export KEY=VALUE`, accepted by POSIX
/// shells and dotenv) only when it is followed by ASCII whitespace, so a key
/// literally named `export` (`export=1`) is not mis-stripped. Handles a tab or a
/// run of spaces, not just the single space the old `strip_prefix("export ")`
/// matched (which missed `export\tKEY=…`).
fn strip_export_prefix(line: &str) -> &str {
    match line.strip_prefix("export") {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_whitespace()) => rest.trim_start(),
        _ => line,
    }
}

/// Strip surrounding ASCII quotes (`"`, `'`, or `` ` ``) when the closing quote
/// is followed only by whitespace or an inline `# comment ...`; otherwise drop
/// any trailing inline comment segment and return the trimmed remainder.
fn unquote_env_value(s: &str) -> String {
    if let Some((&quote, _)) = s.as_bytes().split_first() {
        if matches!(quote, b'"' | b'\'' | b'`') {
            if let Some(closing_idx) = closing_quote_idx(s, quote) {
                let trailing = s[closing_idx + 1..].trim_start();
                if trailing.is_empty() || trailing.starts_with('#') {
                    return s[1..closing_idx].to_string();
                }
            }
        }
    }
    if let Some(hash_idx) = find_inline_comment(s) {
        return s[..hash_idx].trim_end().to_string();
    }
    s.to_string()
}

fn closing_quote_idx(s: &str, quote: u8) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut idx = 1;
    while idx < bytes.len() {
        if bytes[idx] == b'\\' {
            idx += 2;
            continue;
        }
        if bytes[idx] == quote {
            return Some(idx);
        }
        idx += 1;
    }
    None
}

/// Return the byte offset of an inline `# comment` start, when the `#`
/// is preceded by ASCII whitespace. `None` if no such position exists.
fn find_inline_comment(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    bytes
        .windows(2)
        .position(|w| w[0].is_ascii_whitespace() && w[1] == b'#')
        .map(|i| i + 1)
}
