//! Unicode-escape decode-through: resolve `\uXXXX` and `\xXX` escapes (plus
//! single-character backslash escapes) before pattern matching.
//!
//! Secrets are frequently embedded as JSON/JS/source-string literals where the
//! interesting bytes hide behind `\u00..`/`\x..` escapes. Decoding them lets the
//! scanner match the literal credential. Shares the `\uXXXX` hex reader with the
//! JSON and URL decoders via [`super::util::take_hex_digits`].

use super::util::take_hex_digits;

/// Decode backslash escapes (`\uXXXX`, `\xXX`, and `\<char>`) in `input`.
///
/// Returns `Err(())` on a truncated/invalid escape so the caller can skip the
/// candidate rather than emit a corrupted decode.
pub(super) fn unicode_escape_decode(input: &str) -> Result<String, ()> {
    let mut decoded_text = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded_text.push(ch);
            continue;
        }
        match chars.next() {
            Some('u') => {
                let code = take_hex_digits(&mut chars, 4)?;
                decoded_text.push(char::from_u32(code).ok_or(())?);
            }
            Some('x') => {
                let code = take_hex_digits(&mut chars, 2)?;
                decoded_text.push(char::from_u32(code).ok_or(())?);
            }
            Some(escaped) => decoded_text.push(escaped),
            None => return Err(()),
        }
    }
    Ok(decoded_text)
}
