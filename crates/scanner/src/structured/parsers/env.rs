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
pub fn parse_env(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    for (line_idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let after_export = trimmed.strip_prefix("export ").unwrap_or(trimmed);
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

/// Strip surrounding ASCII quotes (`"`, `'`, or `` ` ``) when both ends
/// match; otherwise drop any trailing inline `# comment ...` segment and
/// return the trimmed remainder.
fn unquote_env_value(s: &str) -> String {
    if s.len() >= 2 {
        let first = s.as_bytes()[0];
        let last = s.as_bytes()[s.len() - 1];
        if matches!(first, b'"' | b'\'' | b'`') && first == last {
            return s[1..s.len() - 1].to_string();
        }
    }
    if let Some(hash_idx) = find_inline_comment(s) {
        return s[..hash_idx].trim_end().to_string();
    }
    s.to_string()
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
