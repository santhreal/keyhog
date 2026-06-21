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

    let tokens: Vec<&str> = value.split_whitespace().collect();
    if tokens.len() >= 2 {
        let all_alpha = tokens
            .iter()
            .all(|t| t.len() >= 2 && t.bytes().all(|b| b.is_ascii_alphabetic()));
        if all_alpha {
            let has_lowercase_word = tokens
                .iter()
                .any(|t| t.len() >= 3 && t.bytes().all(|b| b.is_ascii_lowercase()));
            if has_lowercase_word {
                return true;
            }
        }
    }

    false
}
