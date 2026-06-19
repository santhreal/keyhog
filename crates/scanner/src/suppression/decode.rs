//! Base64 decode-and-recheck helper. Used by the suppression decision tree
//! to peek inside a candidate that *might* be a base64-wrapped fixture
//! (kubernetes-secret `data:` fields, dockerconfigjson auth blobs) so the
//! inner suppression gates can fire on the decoded payload.

/// Try to decode `credential` as standard or url-safe base64 and
/// return the result as UTF-8 if successful. Returns `None` on any
/// decode failure or non-UTF-8 payload.
///
/// Used by the suppression gate to peek inside base64-wrapped
/// fixtures whose outer shape looks generic but whose decoded
/// content is a known placeholder / hash / ARN / UUID.
pub(super) fn try_decode_b64_to_utf8(credential: &str) -> Option<String> {
    // Keep only the suppression-specific floor here. Padding, alphabet,
    // variant, and the DoS ceiling are owned by `decode::base64_decode`.
    if credential.len() < 8 {
        return None;
    }
    let bytes = match crate::decode::base64_decode(credential) {
        Ok(bytes) => bytes,
        Err(_) => return None, // LAW10: decode peek miss keeps original candidate unsuppressed, recall-preserving.
    };
    match String::from_utf8(bytes) {
        Ok(text) => Some(text),
        Err(_) => None, // LAW10: non-UTF-8 decoded payload cannot carry plaintext fixture markers; no suppression fires, recall-preserving.
    }
}
