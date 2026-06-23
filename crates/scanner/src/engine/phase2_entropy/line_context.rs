//! Same-line ownership checks for entropy fallback candidates.

use super::helpers::keyword_is_credential_anchor;
use crate::types::ScannerPreprocessedText;

/// True iff the value's own line carries a STRONG credential keyword anchor
/// (`api_key`/`secret`/`token`/`password`/… immediately before a `=`/`:`),
/// i.e. the value is the right-hand side of a direct `KEYWORD = <value>`
/// assignment — not merely on a line within ±1 of a credential keyword. The
/// canonical-shape generation lift is restricted to this surface so the model
/// only ever arbitrates a UUID/hex that is genuinely the assigned secret.
pub(super) fn value_line_has_same_line_credential_keyword(
    entropy_match: &crate::entropy::EntropyMatch,
    preprocessed: &ScannerPreprocessedText<'_>,
    line_offsets: &[usize],
) -> bool {
    let Some(line_text) = entropy_value_line(entropy_match, preprocessed, line_offsets) else {
        return false;
    };
    crate::entropy::keywords::line_has_credential_assignment_surface(line_text)
        || value_owned_by_local_credential_key(line_text, &entropy_match.value)
}

pub(super) fn value_line_has_random_byte_blob_owner(
    entropy_match: &crate::entropy::EntropyMatch,
    preprocessed: &ScannerPreprocessedText<'_>,
    line_offsets: &[usize],
) -> bool {
    let Some(line_text) = entropy_value_line(entropy_match, preprocessed, line_offsets) else {
        return false;
    };
    value_owned_by_local_key_matching(line_text, &entropy_match.value, |normalized| {
        random_byte_assignment_key_is_high_signal(normalized)
    })
}

pub(crate) fn entropy_value_line<'a>(
    entropy_match: &crate::entropy::EntropyMatch,
    preprocessed: &'a ScannerPreprocessedText<'_>,
    line_offsets: &[usize],
) -> Option<&'a str> {
    let line_idx = entropy_match.line.saturating_sub(1);
    if let Some(&line_start) = line_offsets.get(line_idx) {
        let line_end = line_offsets
            .get(line_idx + 1)
            .copied()
            .unwrap_or(preprocessed.text.len()); // LAW10: bounds-checked next-line offset; last line => end-of-text span, recall-safe boundary default
        if let Some(line_text) = preprocessed.text.get(line_start..line_end) {
            if line_text.contains(entropy_match.value.as_str()) {
                return Some(line_text);
            }
        }
    }

    let offset = crate::engine::floor_char_boundary(
        preprocessed.text.as_ref(),
        entropy_match.offset.min(preprocessed.text.len()),
    );
    let before_offset = preprocessed.text.get(..offset)?;
    let at_offset = preprocessed.text.get(offset..)?;
    let line_start = before_offset
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0); // LAW10: no preceding newline => first line start, recall-safe boundary default
    let line_end = at_offset
        .find('\n')
        .map(|relative| offset + relative)
        .unwrap_or(preprocessed.text.len()); // LAW10: no following newline => last line end, recall-safe boundary default
    let line_text = preprocessed.text.get(line_start..line_end)?;
    line_text
        .contains(entropy_match.value.as_str())
        .then_some(line_text)
}

fn value_owned_by_local_credential_key(line: &str, value: &str) -> bool {
    value_owned_by_local_key_matching(line, value, |normalized| {
        crate::entropy::keywords::normalized_assignment_keyword_is_credential(normalized)
            || keyword_is_credential_anchor(normalized)
    })
}

fn value_owned_by_local_key_matching(
    line: &str,
    value: &str,
    accepts: impl Fn(&str) -> bool,
) -> bool {
    let Some(value_start) = line.find(value) else {
        return false;
    };
    let before_value = &line[..value_start];
    for (sep_idx, _) in before_value
        .char_indices()
        .rev()
        .filter(|(_, ch)| matches!(ch, '=' | ':'))
    {
        let lhs = &before_value[..sep_idx];
        let Some(key) = lhs
            .rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')))
            .find(|part| !part.is_empty())
        else {
            continue;
        };
        if let Some(normalized) =
            crate::engine::phase2_generic::keywords::normalize_assignment_keyword(key)
        {
            if accepts(&normalized) {
                return true;
            }
        }
    }
    false
}

fn random_byte_assignment_key_is_high_signal(normalized: &str) -> bool {
    let compact: String = normalized
        .bytes()
        .filter(|b| !matches!(b, b'_' | b'-' | b'.'))
        .map(|b| b.to_ascii_lowercase() as char)
        .collect();
    let separated_suffix =
        normalized.contains('_') && matches!(normalized.rsplit('_').next(), Some("key" | "token"));
    separated_suffix
        || matches!(compact.as_str(), "token" | "bearer" | "authorization")
        || compact.contains("apikey")
        || compact.contains("apitoken")
        || compact.contains("accesskey")
        || compact.contains("authkey")
        || compact.contains("privatekey")
        || compact.contains("signingkey")
        || compact.contains("encryptionkey")
        || compact.contains("sessionkey")
}
