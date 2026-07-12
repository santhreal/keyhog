/// Heuristic for "this value looks like an English-prose run", not a
/// credential. Tightens FP filtering when the keyword-anchor is weak
/// and when quoted-value plausibility sees captured prose.
pub(crate) fn looks_like_english_prose(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 16 {
        return false;
    }

    if bytes.iter().all(|b| b.is_ascii_lowercase()) && bytes.len() >= 16 {
        return true;
    }

    let mut count = 0usize;
    let mut all_alpha = true;
    let mut has_lowercase_word = false;
    for t in value.split_whitespace() {
        count += 1;
        if t.len() < 2 || !t.bytes().all(|b| b.is_ascii_alphabetic()) {
            all_alpha = false;
            break;
        }
        if t.len() >= 3 && t.bytes().all(|b| b.is_ascii_lowercase()) {
            has_lowercase_word = true;
        }
    }

    count >= 2 && all_alpha && has_lowercase_word
}

#[cfg(test)]
mod tests {
    use super::looks_like_english_prose;

    #[test]
    fn english_prose_single_pass_preserves_verdicts() {
        // All-lowercase >=16 (first branch).
        assert!(looks_like_english_prose("abcdefghijklmnop"));
        // Multi-word all-alpha with a lowercase word (second branch).
        assert!(looks_like_english_prose("Session opened with handle XYZ"));
        // Under the 16-byte floor rejects.
        assert!(!looks_like_english_prose("abcdefghijklmno"));
        // A non-alpha token (digits) breaks the all-alpha requirement.
        assert!(!looks_like_english_prose("hello world 12345 foobar"));
        // Multi-word but no all-lowercase word (all mixed/upper).
        assert!(!looks_like_english_prose("AA BB CC DD EE FF GG HH"));
    }
}
