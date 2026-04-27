/// Fast check for secret-related keywords in file content.
/// Used to gate the multiline fallback — only files that mention
/// secret/key/token/password are worth reassembling.
pub(super) fn has_secret_keyword_fast(data: &[u8]) -> bool {
    // Only check for prefixes that are BOTH (a) distinctive enough to be real
    // secrets and (b) commonly split across lines in source code.
    // Avoid short prefixes like AKIA/eyJ that appear in test fixtures.
    const KEYWORDS: &[&[u8]] = &[b"sk-proj-", b"sk_live_", b"ghp_", b"xoxb-", b"xoxp-"];
    for kw in KEYWORDS {
        if memchr::memmem::find(data, kw).is_some() {
            return true;
        }
    }
    false
}

/// Check for generic `secret=`, `password:`, `token=` etc. keywords.
/// Broader than `has_secret_keyword_fast` (which is for multiline only).
pub(super) fn has_generic_assignment_keyword(data: &[u8]) -> bool {
    const KEYWORDS: &[&[u8]] = &[
        b"secret",
        b"SECRET",
        b"password",
        b"PASSWORD",
        b"passwd",
        b"PASSWD",
        b"token",
        b"TOKEN",
        b"api_key",
        b"API_KEY",
        b"apikey",
        b"APIKEY",
        b"auth_token",
        b"AUTH_TOKEN",
        b"private_key",
        b"PRIVATE_KEY",
        b"client_secret",
        b"CLIENT_SECRET",
        b"access_key",
        b"ACCESS_KEY",
    ];
    for kw in KEYWORDS {
        if memchr::memmem::find(data, kw).is_some() {
            return true;
        }
    }
    false
}

/// Per-detector minimum entropy threshold for generic detectors.
///
/// Different secret formats have inherently different entropy profiles:
/// - Random hex tokens (e.g., npm tokens): ~3.7-4.0
/// - Base64 tokens (e.g., JWTs): ~5.0-5.5
/// - UUID-based keys (e.g., some Heroku tokens): ~3.0-3.3
/// - Short API keys with fixed alphabets: ~3.2-3.8
///
/// A blanket 3.5 floor causes false negatives on UUID-style and
/// short fixed-alphabet tokens. This function returns the appropriate
/// floor based on the credential length and detector type.
pub(super) fn generic_entropy_floor(detector_id: &str, credential_len: usize) -> f64 {
    match detector_id {
        // UUID-based tokens have lower entropy due to hex + dashes
        "generic-api-key" if credential_len <= 40 => 2.8,
        // Short tokens with restricted alphabets
        "generic-api-key" if credential_len <= 24 => 3.0,
        // Long random strings need higher entropy to distinguish from code
        "generic-api-key" => 3.5,
        // Password fields can be anything
        "generic-password" => 2.5,
        // Database connection strings have structure
        "generic-database-url" => 2.0,
        // Default: original threshold
        _ => 3.5,
    }
}

pub(super) fn looks_like_variable_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub(super) fn extend_known_prefix_credential<'a>(
    data: &'a str,
    credential: &'a str,
    match_start: usize,
    match_end: usize,
) -> (&'a str, usize) {
    if crate::confidence::known_prefix_confidence_floor(credential).is_none() {
        return (credential, match_end);
    }

    let bytes = data.as_bytes();
    let mut end = match_end;
    while end < bytes.len() && is_provider_token_byte(bytes[end]) {
        end += 1;
    }

    if end == match_end || !data.is_char_boundary(end) {
        return (credential, match_end);
    }

    (&data[match_start..end], end)
}

fn is_provider_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}
