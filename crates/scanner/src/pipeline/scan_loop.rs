use crate::types::*;

pub fn is_within_hex_context(data: &str, match_start: usize, match_end: usize) -> bool {
    if !valid_match_bounds(data, match_start, match_end) {
        return false;
    }
    let matched = &data[match_start..match_end];
    // Cheap rejects FIRST. The earlier flow always walked the
    // matched-string to count hex digits before checking the length
    // floor - wasted work for the (very common) sub-16-byte AC
    // matches that can't possibly meet the threshold. Reordering
    // skips the count entirely on those.
    if matched.len() < MIN_HEX_MATCH_LEN {
        return false;
    }
    if !has_at_least_n_hex_digits(matched, MIN_HEX_DIGITS_IN_MATCH) {
        return false;
    }
    let (before, after) = surrounding_hex_context(data, match_start, match_end);
    let hex_before = formatted_hex_run(before.chars().rev());
    let hex_after = formatted_hex_run(after.chars());
    hex_before >= MIN_HEX_CONTEXT_DIGITS && hex_after >= MIN_HEX_CONTEXT_DIGITS
}

/// Returns true as soon as `n` ASCII hex digits have been seen in `s`.
/// Walking the full string just to compare a count to a threshold is
/// wasted - for matches with no hex shape at all we exit after a
/// handful of bytes; for hex-heavy matches the threshold is cleared
/// long before the end of the credential.
fn has_at_least_n_hex_digits(s: &str, n: usize) -> bool {
    if n == 0 {
        return true;
    }
    let mut seen = 0usize;
    for &b in s.as_bytes() {
        if b.is_ascii_hexdigit() {
            seen += 1;
            if seen >= n {
                return true;
            }
        }
    }
    false
}

fn valid_match_bounds(data: &str, match_start: usize, match_end: usize) -> bool {
    match_end > match_start
        && data.is_char_boundary(match_start)
        && data.is_char_boundary(match_end)
}

fn surrounding_hex_context(data: &str, match_start: usize, match_end: usize) -> (&str, &str) {
    let context_start = crate::engine::floor_char_boundary(
        data,
        match_start.saturating_sub(HEX_CONTEXT_RADIUS_CHARS),
    );
    let context_end = {
        let mut end = (match_end + HEX_CONTEXT_RADIUS_CHARS).min(data.len());
        while end < data.len() && !data.is_char_boundary(end) {
            end += 1;
        }
        end.min(data.len())
    };
    (
        &data[context_start..match_start],
        &data[match_end..context_end],
    )
}

fn formatted_hex_run(iter: impl Iterator<Item = char>) -> usize {
    let mut hex_digits = 0usize;
    let mut separators = 0usize;
    let mut seen_hex = false;

    for ch in iter {
        if ch.is_ascii_hexdigit() {
            hex_digits += 1;
            seen_hex = true;
            continue;
        }
        if matches!(ch, ' ' | '\t' | ':' | '-')
            && (!seen_hex || separators < MAX_HEX_CONTEXT_SEPARATORS)
        {
            separators += 1;
            continue;
        }
        break;
    }

    hex_digits
}

pub fn match_entropy(data: &[u8]) -> f64 {
    #[cfg(feature = "entropy")]
    {
        crate::entropy::shannon_entropy(data)
    }

    #[cfg(not(feature = "entropy"))]
    {
        fallback_entropy(data)
    }
}

#[cfg(not(feature = "entropy"))]
fn fallback_entropy(data: &[u8]) -> f64 {
    // Delegate to the maintained 8-way scalar histogram (with null-run
    // fast-path + log2-table). entropy_fast is feature-independent, so this
    // avoids carrying a stale, less-optimized fork of the same algorithm.
    crate::entropy_fast::shannon_entropy_scalar(data)
}
