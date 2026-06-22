//! Example / placeholder credential detection.
//!
//! These heuristics are a VALUE-SHAPE responsibility, orthogonal to the
//! line-context inference in [`super::inference`]: they look only at the
//! credential string itself (its bytes, prefix, hex/sequential structure) and
//! decide whether it is a documentation placeholder, masking filler, or an
//! empty-input hash that is never a real secret. No hardcoded credential lists -
//! every suppression is based on a structural property that generalizes to all
//! credentials of that shape. Kept separate so the placeholder heuristics can be
//! tested and tuned without dragging in the surrounding-lines machinery.

/// Detect example/placeholder credentials using ONLY algorithmic heuristics.
/// No hardcoded credential lists - every suppression is based on a structural
/// property that generalizes to all credentials of that shape.
pub(crate) fn is_known_example_credential(credential: &str) -> bool {
    let upper = credential.to_uppercase();

    // EXAMPLE/EXAMPLEKEY is a universal documentation convention.
    if upper.ends_with("EXAMPLE") || upper.ends_with("EXAMPLEKEY") {
        return true;
    }

    // x/X-dominated values are masking filler.
    let body = credential.as_bytes();
    let x_count = body.iter().filter(|&&b| b == b'x' || b == b'X').count();
    if body.len() >= 16 && x_count > body.len() * 3 / 4 {
        return true;
    }

    // Ascending hex pairs are documentation placeholders.
    if is_hex_sequential_placeholder(credential) {
        return true;
    }

    // These appear in integrity checks, not as secrets.
    if is_empty_input_hash(credential) {
        return true;
    }

    // Monotonic or repetitive bodies remain placeholders after stripping prefixes.
    is_sequential_placeholder(credential)
}

/// Returns true if the credential is the hash of an empty input (common in
/// integrity/checksum fields, never a real secret).
fn is_empty_input_hash(credential: &str) -> bool {
    let lower = credential.to_ascii_lowercase();
    // Only match exact lengths to avoid false positives on substrings.
    match lower.len() {
        32 => lower == "d41d8cd98f00b204e9800998ecf8427e", // MD5("")
        40 => lower == "da39a3ee5e6b4b0d3255bfef95601890afd80709", // SHA1("")
        64 => lower == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // SHA256("")
        _ => false,
    }
}

pub(crate) fn is_sequential_placeholder(credential: &str) -> bool {
    // Strip ALL known service prefixes before checking for sequential/placeholder patterns.
    // Single source of truth: crate::confidence::KNOWN_PREFIXES.
    // Missing a prefix here = false positive (placeholder not suppressed).
    let body = crate::confidence::KNOWN_PREFIXES
        .iter()
        .find_map(|prefix| credential.strip_prefix(prefix))
        .unwrap_or(credential); // LAW10: no known prefix present ⇒ body IS the whole credential (intended suppression logic, not an error swallow); recall-safe and O(prefixes), no slower path.
    if body.len() < 8 {
        return false;
    }

    let bytes = body.as_bytes();
    if bytes.iter().all(|&byte| byte == bytes[0]) {
        return true;
    }
    if bytes.len() >= 8 {
        let pair = &bytes[..2];
        if bytes
            .chunks(2)
            .all(|chunk| chunk == pair || (chunk.len() < 2 && chunk[0] == pair[0]))
        {
            return true;
        }
    }
    false
}

fn is_hex_sequential_placeholder(credential: &str) -> bool {
    // Same canonical prefix list as is_sequential_placeholder. Strip the
    // prefix before the hex-sequence check so e.g. `ghp_0123456789abcdef`
    // still trips the "monotonic hex" suppression on the BODY.
    let body = crate::confidence::KNOWN_PREFIXES
        .iter()
        .find_map(|prefix| credential.strip_prefix(prefix))
        .unwrap_or(credential); // LAW10: no known prefix present ⇒ body IS the whole credential (intended; the hex-sequence check then runs on the full value); recall-safe, no slower path.

    if body.len() < 16 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }

    let bytes: Vec<u8> = body.bytes().collect();

    // Single-byte monotonic sequences such as 0123456789abcdef or fedcba9876543210.
    if bytes.len() >= 16 {
        let ascending = bytes
            .windows(2)
            .filter(|w| {
                w[1] == w[0] + 1 || (w[0] == b'9' && w[1] == b'a') || (w[0] == b'f' && w[1] == b'0')
            })
            .count();
        let descending = bytes
            .windows(2)
            .filter(|w| {
                w[1] + 1 == w[0] || (w[0] == b'a' && w[1] == b'9') || (w[0] == b'0' && w[1] == b'f')
            })
            .count();
        let threshold = (bytes.len() - 1) * 9 / 10;
        if ascending > threshold || descending > threshold {
            return true;
        }
    }

    let pairs: Vec<&[u8]> = bytes.chunks(2).filter(|chunk| chunk.len() == 2).collect();
    if pairs.len() < 8 {
        return false;
    }

    let first_chars: Vec<u8> = pairs
        .iter()
        .map(|pair| pair[0].to_ascii_lowercase())
        .collect();
    let ascending = first_chars
        .windows(2)
        .filter(|window| {
            window[1] == window[0] + 1
                || (window[0] == b'f' && window[1] == b'0')
                || (window[0] == b'9' && window[1] == b'a')
                || (window[0] == b'9' && window[1] == b'0')
        })
        .count();

    let second_chars: Vec<u8> = pairs
        .iter()
        .map(|pair| pair[1].to_ascii_lowercase())
        .collect();
    let ascending2 = second_chars
        .windows(2)
        .filter(|window| {
            window[1] == window[0] + 1
                || (window[0] == b'f' && window[1] == b'0')
                || (window[0] == b'9' && window[1] == b'0')
                || (window[0] == b'9' && window[1] == b'a')
        })
        .count();

    let threshold = pairs.len() * 9 / 10;
    ascending > threshold && ascending2 > threshold
}
