/// Fast check for secret-related keywords in file content.
/// Used to gate the multiline fallback — only files that mention
/// secret/key/token/password are worth reassembling.
///
/// Only the Hyperscan-prefilter path of `scan_coalesced` calls this,
/// so gate it on `simd` to avoid a dead-code warning in the
/// no-Hyperscan Windows build.
///
/// Single-pass Aho-Corasick over all distinctive prefixes — replaces the
/// previous loop of N independent `memmem` scans (each O(n)) which traversed
/// the chunk N times. With the AC automaton the scan is O(n) total, with
/// one memory walk and shared cache lines.
#[cfg(feature = "simd")]
pub(super) fn has_secret_keyword_fast(data: &[u8]) -> bool {
    use aho_corasick::AhoCorasick;
    use once_cell::sync::Lazy;
    static AC: Lazy<AhoCorasick> = Lazy::new(|| {
        // Distinctive enough to be real secrets AND commonly split across
        // lines in source code. Avoid short prefixes like AKIA/eyJ that
        // appear in test fixtures.
        AhoCorasick::new(["sk-proj-", "sk_live_", "ghp_", "xoxb-", "xoxp-"])
            .expect("static keyword set compiles")
    });
    AC.find(data).is_some()
}

/// Check for generic `secret=`, `password:`, `token=` etc. keywords.
/// Broader than `has_secret_keyword_fast` (which is for multiline only).
///
/// Same single-pass AC strategy as `has_secret_keyword_fast`, but with the
/// case-insensitive variants folded into one automaton — `aho-corasick`'s
/// `ascii_case_insensitive` builder option matches both `secret` and
/// `SECRET` from a single literal at scan-time, halving the pattern count.
///
/// Same simd gate as [`has_secret_keyword_fast`] — only the
/// Hyperscan-prefilter path consumes it.
#[cfg(feature = "simd")]
pub(super) fn has_generic_assignment_keyword(data: &[u8]) -> bool {
    use aho_corasick::AhoCorasick;
    use once_cell::sync::Lazy;
    static AC: Lazy<AhoCorasick> = Lazy::new(|| {
        AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build([
                "secret",
                "password",
                "passwd",
                "token",
                "api_key",
                "apikey",
                "auth_token",
                "private_key",
                "client_secret",
                "access_key",
            ])
            .expect("static keyword set compiles")
    });
    AC.find(data).is_some()
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
