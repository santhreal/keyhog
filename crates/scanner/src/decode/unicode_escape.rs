//! Unicode-escape decode-through: resolve `\uXXXX` and `\xXX` escapes (plus
//! single-character backslash escapes) before pattern matching.
//!
//! Secrets are frequently embedded as JSON/JS/source-string literals where the
//! interesting bytes hide behind `\u00..`/`\x..` escapes. Decoding them lets the
//! scanner match the literal credential. Shares hex readers and lazy output
//! allocation with the other decoders via [`super::util`].

use super::util::{lazy_decoded_prefix, take_hex_digits_indexed};

/// Decode backslash escapes (`\uXXXX`, `\xXX`, and `\<char>`) in `input`.
///
/// Returns `Err(())` on a truncated/invalid escape so the caller can skip the
/// candidate rather than emit a corrupted decode.
pub(super) fn unicode_escape_decode(input: &str) -> Result<String, ()> {
    let mut decoded_text: Option<String> = None;
    let mut chars = input.char_indices().peekable();
    while let Some((idx, ch)) = chars.next() {
        if ch != '\\' {
            if let Some(decoded_text) = decoded_text.as_mut() {
                decoded_text.push(ch);
            }
            continue;
        }
        match chars.next().map(|(_, escaped)| escaped) {
            Some('u') => {
                let code = take_hex_digits_indexed(&mut chars, 4)?;
                lazy_decoded_prefix(&mut decoded_text, input, idx)
                    .push(char::from_u32(code).ok_or(())?);
            }
            Some('x') => {
                let code = take_hex_digits_indexed(&mut chars, 2)?;
                lazy_decoded_prefix(&mut decoded_text, input, idx)
                    .push(char::from_u32(code).ok_or(())?);
            }
            Some(escaped) => {
                lazy_decoded_prefix(&mut decoded_text, input, idx).push(simple_escape(escaped));
            }
            None => return Err(()),
        }
    }
    decoded_text.ok_or(())
}

fn simple_escape(escaped: char) -> char {
    match escaped {
        'b' => '\x08',
        'f' => '\x0c',
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        other => other,
    }
}
