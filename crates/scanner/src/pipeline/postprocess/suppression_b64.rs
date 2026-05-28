/// Try to decode `credential` as standard or url-safe base64 and
/// return the result as UTF-8 if successful. Returns `None` on any
/// decode failure or non-UTF-8 payload.
///
/// Used by the suppression gate to peek inside base64-wrapped
/// fixtures whose outer shape looks generic but whose decoded
/// content is a known placeholder / hash / ARN / UUID.
pub(super) fn try_decode_b64_to_utf8(credential: &str) -> Option<String> {
    // Cheap shape gate before paying for the decode allocation.
    // Standard base64 alphabet (`[A-Za-z0-9+/=]`) and url-safe
    // (`[A-Za-z0-9_\-=]`). Length must be ≥ 8 so we don't waste
    // cycles on every 4-char identifier we see.
    if credential.len() < 8 || credential.len() > 4096 {
        return None;
    }
    let valid = credential.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
    });
    if !valid {
        return None;
    }
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;
    // Try standard, url-safe, and their no-pad variants in order.
    // A no-trait-object array sidesteps the `base64::Engine` non-
    // dyn-compatible trait bound.
    if let Ok(bytes) = STANDARD.decode(credential) {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            return Some(s.to_string());
        }
    }
    if let Ok(bytes) = URL_SAFE.decode(credential) {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            return Some(s.to_string());
        }
    }
    if let Ok(bytes) = STANDARD_NO_PAD.decode(credential) {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            return Some(s.to_string());
        }
    }
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(credential) {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            return Some(s.to_string());
        }
    }
    None
}
