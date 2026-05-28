use crate::shape_gates::*;

pub(super) fn upper_contains_token(upper: &str, token: &str) -> bool {
    upper.match_indices(token).any(|(idx, _)| {
        let before = upper[..idx].chars().next_back();
        let after = upper[idx + token.len()..].chars().next();
        before.is_none_or(|c| !c.is_alphanumeric()) && after.is_none_or(|c| !c.is_alphanumeric())
    })
}

/// Trim trailing decode/binary garbage before placeholder heuristics run.
pub(super) fn suppression_credential_slice(credential: &str) -> &str {
    credential
        .split('\0')
        .next()
        .unwrap_or(credential)
        .split('\\')
        .next()
        .unwrap_or(credential)
}

/// True if `credential` is a C/Rust-identifier shape rather than a credential.
pub(super) fn looks_like_pure_identifier(credential: &str) -> bool {
    let bytes = credential.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut underscore_count = 0usize;
    let mut has_digit = false;
    for &b in bytes {
        if b == b'_' {
            underscore_count += 1;
        } else if b.is_ascii_digit() {
            has_digit = true;
        } else if !b.is_ascii_alphabetic() {
            return false;
        }
    }
    !has_digit && underscore_count >= 2
}
