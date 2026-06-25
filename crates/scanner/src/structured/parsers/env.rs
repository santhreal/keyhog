use super::ExtractedPair;

/// Parse KEY=VALUE lines from an .env file.
///
/// Quoting styles recognised:
/// - `KEY="value"` and `KEY='value'` (matching ASCII single/double quotes).
/// - `` KEY=`value` `` backtick-quoted bodies (some shells + dotenv-cli
///   accept these).
/// - Bare `KEY=value` with no quotes.
///
/// Inline comments are stripped on UNQUOTED values only. Sample seen in
/// `.env` files: `DB_PASS=p4ssw0rd # rotate quarterly` -> value = `p4ssw0rd`.
/// Quoted values keep `#` because the user has explicitly opted into the
/// literal string including the hash.
pub(crate) fn parse_env(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    for (line_idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let after_export = trimmed.strip_prefix("export ").unwrap_or(trimmed); // LAW10: no prefix/suffix to strip => value unchanged (intended), recall-safe
        if let Some((key, value)) = after_export.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() {
                continue;
            }
            let unquoted = unquote_env_value(value);
            pairs.push(ExtractedPair {
                context: key.to_string(),
                value: unquoted,
                line: line_idx + 1,
            });
        }
    }
    pairs
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
