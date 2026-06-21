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
    let scheme_str = std::str::from_utf8(scheme).unwrap_or("");
    if matches!(
        scheme_str,
        "sha256" | "sha512" | "sha1" | "md5" | "blake3" | "blake2"
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
    let segments: Vec<&str> = value.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() < 2 {
        return false;
    }
    segments.iter().all(|s| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
            && s.bytes().any(|b| b.is_ascii_alphabetic())
    })
}
