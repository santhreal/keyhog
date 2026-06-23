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
    // Missing a prefix here = false positive (placeholder not suppressed).
    let body = credential_body_without_known_prefix(credential);
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
    let body = credential_body_without_known_prefix(credential);

    if body.len() < 16 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }

    let bytes = body.as_bytes();

    // Single-byte monotonic sequences such as 0123456789abcdef or fedcba9876543210.
    if bytes.len() >= 16 {
        let ascending = count_adjacent_hex_steps(bytes, hex_forward_step);
        let descending = count_adjacent_hex_steps(bytes, hex_reverse_step);
        let threshold = (bytes.len() - 1) * 9 / 10;
        if ascending > threshold || descending > threshold {
            return true;
        }
    }

    let pair_count = bytes.len() / 2;
    if pair_count < 8 {
        return false;
    }

    if hex_byte_values_are_sequential(bytes, pair_count) {
        return true;
    }

    let ascending = count_pair_column_hex_steps(bytes, pair_count, 0);
    let ascending2 = count_pair_column_hex_steps(bytes, pair_count, 1);

    let threshold = pair_count * 9 / 10;
    ascending > threshold && ascending2 > threshold
}

fn credential_body_without_known_prefix(credential: &str) -> &str {
    crate::confidence::known_prefix_body(credential).unwrap_or(credential) // LAW10: unknown prefix => inspect full credential body, over-suppresses less, recall-safe
}

fn count_adjacent_hex_steps(bytes: &[u8], step: fn(u8, u8) -> bool) -> usize {
    bytes
        .windows(2)
        .filter(|window| step(window[0], window[1]))
        .count()
}

fn count_pair_column_hex_steps(bytes: &[u8], pair_count: usize, column: usize) -> usize {
    (1..pair_count)
        .filter(|&pair| {
            let previous = bytes[(pair - 1) * 2 + column];
            let next = bytes[pair * 2 + column];
            hex_pair_column_step(previous, next)
        })
        .count()
}

fn hex_byte_values_are_sequential(bytes: &[u8], pair_count: usize) -> bool {
    let forward = count_pair_value_steps(bytes, pair_count, |previous, next| {
        next == previous.wrapping_add(1)
    });
    let reverse = count_pair_value_steps(bytes, pair_count, |previous, next| {
        previous == next.wrapping_add(1)
    });
    let threshold = (pair_count - 1) * 9 / 10;
    forward > threshold || reverse > threshold
}

fn count_pair_value_steps(bytes: &[u8], pair_count: usize, step: fn(u8, u8) -> bool) -> usize {
    let Some(mut previous) = hex_pair_value(bytes, 0) else {
        return 0;
    };
    let mut count = 0usize;
    for pair in 1..pair_count {
        let Some(next) = hex_pair_value(bytes, pair) else {
            return 0;
        };
        if step(previous, next) {
            count += 1;
        }
        previous = next;
    }
    count
}

fn hex_pair_value(bytes: &[u8], pair: usize) -> Option<u8> {
    let hi = crate::decode::util::hex_val(bytes[pair * 2]).ok()?; // LAW10: non-hex pair => not a sequential hex placeholder, so candidate remains reportable
    let lo = crate::decode::util::hex_val(bytes[pair * 2 + 1]).ok()?; // LAW10: non-hex pair => not a sequential hex placeholder, so candidate remains reportable
    Some((hi << 4) | lo)
}

fn hex_forward_step(previous: u8, next: u8) -> bool {
    let previous = previous.to_ascii_lowercase();
    let next = next.to_ascii_lowercase();
    next == previous + 1 || (previous == b'9' && next == b'a') || (previous == b'f' && next == b'0')
}

fn hex_reverse_step(previous: u8, next: u8) -> bool {
    let previous = previous.to_ascii_lowercase();
    let next = next.to_ascii_lowercase();
    next + 1 == previous || (previous == b'a' && next == b'9') || (previous == b'0' && next == b'f')
}

fn hex_pair_column_step(previous: u8, next: u8) -> bool {
    let previous = previous.to_ascii_lowercase();
    let next = next.to_ascii_lowercase();
    hex_forward_step(previous, next) || (previous == b'9' && next == b'0')
}
