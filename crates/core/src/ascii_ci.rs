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

/// Returns true when the last `suffix.len()` bytes of `bytes` equal `suffix`,
/// ignoring ASCII case. Byte-based so it is the ONE owner for both the scanner
/// (which works in `&[u8]`) and the sources crate (string callers pass
/// `value.as_bytes()` / a `b"..."` literal). An empty suffix always matches; a
/// suffix longer than `bytes` never matches.
#[inline]
pub fn ends_with_ignore_ascii_case(bytes: &[u8], suffix: &[u8]) -> bool {
    bytes
        .get(bytes.len().saturating_sub(suffix.len())..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ends_with_exact_case() {
        assert!(ends_with_ignore_ascii_case(b"config.YAML", b".YAML"));
    }

    #[test]
    fn ends_with_mixed_case() {
        assert!(ends_with_ignore_ascii_case(b"archive.TAR.gz", b".tar.GZ"));
    }

    #[test]
    fn ends_with_full_string() {
        assert!(ends_with_ignore_ascii_case(b"EXAMPLE", b"example"));
    }

    #[test]
    fn ends_with_empty_suffix_always_matches() {
        assert!(ends_with_ignore_ascii_case(b"anything", b""));
        assert!(ends_with_ignore_ascii_case(b"", b""));
    }

    #[test]
    fn ends_with_suffix_longer_than_value() {
        assert!(!ends_with_ignore_ascii_case(b".gz", b"archive.gz"));
    }

    #[test]
    fn ends_with_no_match() {
        assert!(!ends_with_ignore_ascii_case(b"file.json", b".yaml"));
    }

    #[test]
    fn ends_with_prefix_only_no_match() {
        // Suffix appears at the front, not the end.
        assert!(!ends_with_ignore_ascii_case(b"yaml.file", b"yaml"));
    }

    #[test]
    fn ends_with_from_str_bytes() {
        let path = "https://host/app.WASM";
        assert!(ends_with_ignore_ascii_case(path.as_bytes(), b".wasm"));
        assert!(!ends_with_ignore_ascii_case(path.as_bytes(), b".map"));
    }
}
