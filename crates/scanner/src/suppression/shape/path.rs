/// True if `value` looks like a URI / URN / scheme-prefixed string.
pub(crate) fn looks_like_scheme_prefixed_uri(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 6 {
        return false;
    }
    let Some(colon_idx) = bytes.iter().position(|&b| b == b':') else {
        return false;
    };
    if !(3..=15).contains(&colon_idx) {
        return false;
    }
    let scheme = &bytes[..colon_idx];
    if !scheme.iter().all(|&b| b.is_ascii_alphabetic() || b == b'-') {
        return false;
    }
    if !scheme.iter().any(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    let after = &bytes[colon_idx + 1..];
    if after.starts_with(b"//") || after.contains(&b':') || scheme.contains(&b'-') {
        return true;
    }
    if matches!(
        scheme,
        b"sha256" | b"sha512" | b"sha1" | b"md5" | b"blake3" | b"blake2"
    ) {
        return true;
    }
    bytes.len() <= 20
        && after.iter().all(|&b| b.is_ascii_alphabetic())
        && !after.is_empty()
        && after.len() <= 10
}

/// True if `value` looks like a `/`-separated path or URL fragment.
pub(crate) fn looks_like_url_or_path_segment(value: &str) -> bool {
    if !value.contains('/') {
        return false;
    }
    let mut count = 0usize;
    let mut all_ok = true;
    for s in value.split('/').filter(|s| !s.is_empty()) {
        count += 1;
        let body_ok = s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
            && s.bytes().any(|b| b.is_ascii_alphabetic());
        if !body_ok {
            all_ok = false;
            break;
        }
    }
    count >= 2 && all_ok
}

pub(crate) fn looks_like_filename_reference(value: &str) -> bool {
    const FILENAME_SUFFIXES: &[&[u8]] = &[
        b".jks",
        b".yml",
        b".yaml",
        b".toml",
        b".json",
        b".properties",
        b".pem",
        b".key",
        b".crt",
        b".cer",
        b".pfx",
        b".p12",
        b".keystore",
        b".truststore",
        b".conf",
        b".ini",
        b".env",
        b".lock",
        b".log",
    ];
    let bytes = value.as_bytes();
    FILENAME_SUFFIXES
        .iter()
        .any(|s| crate::ascii_ci::ends_with_ignore_ascii_case(bytes, s))
}

#[cfg(test)]
mod tests {
    use super::looks_like_url_or_path_segment;

    #[test]
    fn url_or_path_segment_single_pass_preserves_verdicts() {
        // >=2 non-empty segments, each alnum-ish with a letter.
        assert!(looks_like_url_or_path_segment("api/v1/users"));
        assert!(looks_like_url_or_path_segment("a/b"));
        // No slash → not a path.
        assert!(!looks_like_url_or_path_segment("foobar"));
        // Only empty segments after filtering → under the 2-segment floor.
        assert!(!looks_like_url_or_path_segment("///"));
        // Pure-digit segments carry no letter → rejected.
        assert!(!looks_like_url_or_path_segment("12/34"));
    }
}
