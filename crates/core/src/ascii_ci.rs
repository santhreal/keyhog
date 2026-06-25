/// Returns true when `value` starts with `prefix`, ignoring ASCII case.
#[inline]
pub fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

/// Returns true when `value` contains `needle`, ignoring ASCII case.
#[inline]
pub fn contains_ignore_ascii_case(value: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    if needle.is_empty() {
        return true;
    }
    value
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Returns true when `value` contains `needle`, ignoring ASCII case.
#[inline]
pub fn contains_bytes_ignore_ascii_case(value: &str, needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    value
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_with_matches_case_insensitively_and_fails_closed_on_overlong_prefix() {
        assert!(starts_with_ignore_ascii_case("Bearer xyz", "bEaRer"));
        assert!(starts_with_ignore_ascii_case("anything", ""));
        // Boundary: a prefix longer than the value cannot match (no panic, no
        // out-of-bounds slice — `get(..len)` returns None).
        assert!(!starts_with_ignore_ascii_case("ab", "abc"));
        assert!(!starts_with_ignore_ascii_case("Token", "key"));
    }

    #[test]
    fn contains_matches_case_insensitively_with_empty_and_overlong_boundaries() {
        assert!(contains_ignore_ascii_case("X-API-KEY: v", "api-key"));
        // Empty needle is vacuously contained.
        assert!(contains_ignore_ascii_case("", ""));
        // Needle longer than the haystack windows to zero candidates → false.
        assert!(!contains_ignore_ascii_case("ab", "abc"));
        assert!(!contains_ignore_ascii_case("password", "secret"));
    }

    #[test]
    fn ascii_fold_does_not_spuriously_match_multibyte_utf8() {
        // Adversarial: a multibyte UTF-8 char must not case-fold into an ASCII
        // needle. 'Ä' (0xC3 0x84) shares no ASCII-folded bytes with "ax".
        assert!(!contains_ignore_ascii_case("Ä", "ax"));
        assert!(!contains_bytes_ignore_ascii_case("Ä", b"ax"));
        // Bytes API folds ASCII the same way and honors the empty-needle rule.
        assert!(contains_bytes_ignore_ascii_case("AUTHORIZATION", b"author"));
        assert!(contains_bytes_ignore_ascii_case("anything", b""));
        assert!(!contains_bytes_ignore_ascii_case("ab", b"abc"));
    }
}
