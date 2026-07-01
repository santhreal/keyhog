use super::base64::base64_decode;
use super::pipeline::{
    decode_candidate_refs_exact, decode_candidate_spans_exact, with_extracted_value_spans,
    ExtractedValue,
};
use super::unicode_escape::unicode_escape_decode;
use super::util::{hex_val, lazy_decoded_prefix};
use super::Decoder;
use crate::context;
use keyhog_core::Chunk;

pub(super) struct UrlDecoder;
pub(super) struct QuotedPrintableDecoder;
pub(super) struct HtmlNamedEntityDecoder;
pub(super) struct HtmlNumericEntityDecoder;
pub(super) struct OctalEscapeDecoder;
pub(super) struct MimeEncodedWordDecoder;
pub(super) struct UnicodeEscapeDecoder;

impl Decoder for UrlDecoder {
    fn name(&self) -> &'static str {
        "url"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        if !chunk.data.contains('%') {
            return Vec::new();
        }
        with_extracted_value_spans(&chunk.data, |candidates| {
            let mut decoded_chunks = decode_candidate_refs_exact(
                chunk,
                candidates
                    .iter()
                    .filter_map(|candidate| candidate.value.contains('%').then_some(candidate)),
                url_decode,
                self.name(),
            );
            let synthetic = percent_assignment_tail_candidates(&chunk.data, candidates);
            decoded_chunks.extend(decode_candidate_spans_exact(
                chunk,
                synthetic,
                url_decode,
                self.name(),
            ));
            decoded_chunks
        })
    }
}

fn percent_assignment_tail_candidates(
    text: &str,
    borrowed_candidates: &[ExtractedValue],
) -> Vec<ExtractedValue> {
    let mut synthetic = Vec::new();
    // Also pick up percent-only assignment tails the pct_block accumulator
    // can miss when the `%` run abuts a quote or delimiter mid-chunk.
    for line in text.lines() {
        for (lhs, rhs) in line.split_once('=').into_iter().chain(
            line.split_once(':')
                .into_iter()
                .filter(|(l, _)| !l.contains("://") && !l.starts_with("http")),
        ) {
            let _ = lhs; // LAW10: unused-binding marker (signature/borrowck/cfg/compile-time assert); no runtime effect, not a fallback
            let rhs = rhs.trim().trim_matches('"').trim_matches('\'');
            if rhs.starts_with('%')
                && rhs.len() >= 6
                && contains_percent_escape(rhs)
                && !borrowed_candidates.iter().any(|c| c.value.as_str() == rhs)
                && !synthetic.iter().any(|c: &ExtractedValue| c.value == rhs)
            {
                synthetic.push(ExtractedValue::synthetic(rhs.to_string()));
            }
        }
    }
    synthetic
}

impl Decoder for QuotedPrintableDecoder {
    fn name(&self) -> &'static str {
        "quoted-printable"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let line_views = line_views_with_offsets(&chunk.data);
        let lines = line_views.iter().map(|line| line.text).collect::<Vec<_>>();

        with_extracted_value_spans(&chunk.data, |candidates| {
            let mut decoded_chunks = Vec::new();
            for (line_idx, line) in line_views.iter().enumerate() {
                // Cheap O(line) gate FIRST: real Quoted-Printable needs a
                // `=XX` hex escape, and every candidate is a substring of this
                // line, so a line with no `=XX` cannot yield ANY QP candidate.
                // Reuse the whole-chunk extractor view below; per-line
                // extraction misses the shared cache by pointer/len and
                // recomputes the same candidates on every QP-shaped line.
                if !has_qp_escape(line.text) {
                    continue;
                }
                if context::is_false_positive_context(
                    &lines,
                    line_idx,
                    chunk.metadata.path.as_deref(),
                ) {
                    continue;
                }

                decoded_chunks.extend(decode_candidate_refs_exact(
                    chunk,
                    candidates.iter().filter_map(|candidate| {
                        let (start, end) = candidate.span()?;
                        (start >= line.start && end <= line.end && has_qp_escape(&candidate.value))
                            .then_some(candidate)
                    }),
                    quoted_printable_decode,
                    self.name(),
                ));

                if let Some(trimmed) = trimmed_line_candidate(line) {
                    decoded_chunks.extend(decode_candidate_spans_exact(
                        chunk,
                        vec![trimmed],
                        quoted_printable_decode,
                        self.name(),
                    ));
                }
            }
            decoded_chunks
        })
    }
}

struct LineView<'a> {
    text: &'a str,
    start: usize,
    end: usize,
}

fn line_views_with_offsets(text: &str) -> Vec<LineView<'_>> {
    text.split_inclusive('\n')
        .scan(0usize, |offset, segment| {
            let start = *offset;
            *offset += segment.len();
            let line = strip_line_ending(segment);
            Some(LineView {
                text: line,
                start,
                end: start + line.len(),
            })
        })
        .collect()
}

fn strip_line_ending(segment: &str) -> &str {
    let line = segment.strip_suffix('\n').unwrap_or(segment); // LAW10: recall-preserving identity for final unterminated lines; whole-line bytes still flow to scanning.
    line.strip_suffix('\r').unwrap_or(line) // LAW10: recall-preserving identity when no CR is present; whole-line bytes still flow to scanning.
}

fn trimmed_line_candidate(line: &LineView<'_>) -> Option<ExtractedValue> {
    let trimmed = line.text.trim();
    if trimmed.is_empty() || !trimmed.contains('=') || !has_qp_escape(trimmed) {
        return None;
    }
    let leading = line.text.len() - line.text.trim_start().len();
    let trailing = line.text.trim_end().len();
    Some(ExtractedValue::new(
        trimmed.to_string(),
        line.start + leading,
        line.start + trailing,
    ))
}

/// True if `s` contains at least one well-formed Quoted-Printable
/// escape (`=XX` where `XX` is two hex digits). Trailing-bare-`=`
/// inputs and `key=value` text return false and skip the decode.
fn has_qp_escape(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes
        .windows(3)
        .any(|w| w[0] == b'=' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
}

macro_rules! simple_decoder {
    ($decoder:ty, $name:literal, $filter:expr, $decode:ident) => {
        impl Decoder for $decoder {
            fn name(&self) -> &'static str {
                $name
            }

            fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
                let mut decoded_chunks = with_extracted_value_spans(&chunk.data, |candidates| {
                    decode_candidate_refs_exact(
                        chunk,
                        candidates.iter().filter_map(|candidate| {
                            ($filter)(candidate.value.as_str()).then_some(candidate)
                        }),
                        $decode,
                        self.name(),
                    )
                });
                let trimmed = chunk.data.trim();
                if ($filter)(trimmed) && !trimmed.is_empty() {
                    decoded_chunks.extend(decode_candidate_spans_exact(
                        chunk,
                        vec![ExtractedValue::synthetic(trimmed.to_string())],
                        $decode,
                        self.name(),
                    ));
                }
                decoded_chunks
            }
        }
    };
}

simple_decoder!(
    HtmlNamedEntityDecoder,
    "html-named-entity",
    |s: &str| s.contains('&'),
    html_named_entity_decode
);
simple_decoder!(
    HtmlNumericEntityDecoder,
    "html-numeric-entity",
    |s: &str| s.contains("&#"),
    html_numeric_entity_decode
);
simple_decoder!(
    OctalEscapeDecoder,
    "octal-escape",
    contains_octal_escape,
    octal_escape_decode
);
simple_decoder!(
    UnicodeEscapeDecoder,
    "unicode-escape",
    |s: &str| s.contains("\\u") || s.contains("\\x"),
    unicode_escape_decode
);

impl Decoder for MimeEncodedWordDecoder {
    fn name(&self) -> &'static str {
        "mime-encoded-word"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        decode_candidate_spans_exact(
            chunk,
            find_mime_encoded_word_spans(&chunk.data),
            mime_encoded_word_decode,
            self.name(),
        )
    }
}

fn percent_decode(input: &str) -> Result<String, ()> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut index = 0;
    let input_bytes = input.as_bytes();
    while index < input_bytes.len() {
        if let Some(pct_idx) = memchr::memchr(b'%', &input_bytes[index..]) {
            bytes.extend_from_slice(&input_bytes[index..index + pct_idx]);
            index += pct_idx;

            if index + 2 >= input_bytes.len() {
                return Err(());
            }
            let high = hex_val(input_bytes[index + 1])?;
            let low = hex_val(input_bytes[index + 2])?;
            bytes.push((high << 4) | low);
            index += 3;
        } else {
            bytes.extend_from_slice(&input_bytes[index..]);
            break;
        }
    }
    String::from_utf8(bytes).map_err(|_| ())
}

fn url_decode(input: &str) -> Result<String, ()> {
    // kimi-decode audit: bail before doing any work when there is no
    // valid `%XX` percent-escape in the candidate. The previous flow
    // copied trailing bare `%` or `%X` (one-char-short) unchanged and
    // returned the identical string - wasted decode work that the
    // `seen` dedup later dropped. Refuse the candidate earlier.
    if !contains_percent_escape(input) {
        return Err(());
    }
    percent_decode(input)
}

fn contains_percent_escape(input: &str) -> bool {
    input
        .as_bytes()
        .windows(3)
        .any(|window| window[0] == b'%' && hex_val(window[1]).is_ok() && hex_val(window[2]).is_ok())
}

pub(crate) fn quoted_printable_decode(input: &str) -> Result<String, ()> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut index = 0;
    let input_bytes = input.as_bytes();
    while index < input_bytes.len() {
        if let Some(eq_idx) = memchr::memchr(b'=', &input_bytes[index..]) {
            bytes.extend_from_slice(&input_bytes[index..index + eq_idx]);
            index += eq_idx;

            // `index` points at the `=`; classify what follows.
            match input_bytes.get(index + 1) {
                // Soft line break: a QP `=` immediately before a line ending is a
                // continuation marker and is removed together with the newline.
                // RFC2045 specifies CRLF, but real-world QP (Unix-origin MIME,
                // git-format mail) also emits a bare `=\n`, and occasionally a lone
                // `=\r`; handling all three keeps a secret a QP encoder wrapped
                // across a soft break contiguous instead of injecting a spurious
                // `=` + newline. A literal `=` is always encoded `=3D`, so a raw
                // `=` before a newline is unambiguously a soft break and this can
                // never consume a real byte.
                Some(b'\n') => index += 2,
                Some(b'\r') => {
                    index += if input_bytes.get(index + 2) == Some(&b'\n') {
                        3
                    } else {
                        2
                    };
                }
                // `=XX` hex octet: exactly two hex digits after the `=`.
                Some(&first) => {
                    match (
                        hex_val(first),
                        input_bytes.get(index + 2).map(|&b| hex_val(b)),
                    ) {
                        (Ok(high), Some(Ok(low))) => {
                            bytes.push((high << 4) | low);
                            index += 3;
                        }
                        // Non-hex, or the octet is truncated at end-of-input: the
                        // `=` is a literal byte.
                        _ => {
                            bytes.push(b'=');
                            index += 1;
                        }
                    }
                }
                // `=` is the final byte of the input: literal.
                None => {
                    bytes.push(b'=');
                    index += 1;
                }
            }
        } else {
            bytes.extend_from_slice(&input_bytes[index..]);
            break;
        }
    }
    String::from_utf8(bytes).map_err(|_| ())
}

fn html_named_entity_decode(input: &str) -> Result<String, ()> {
    let mut decoded: Option<String> = None;
    let mut chars = input.char_indices().peekable();

    while let Some((idx, ch)) = chars.next() {
        if ch != '&' {
            if let Some(decoded) = decoded.as_mut() {
                decoded.push(ch);
            }
            continue;
        }

        let mut entity = String::new();
        while let Some(&(_, next)) = chars.peek() {
            entity.push(next);
            chars.next();
            if next == ';' || entity.len() > 10 {
                break;
            }
        }

        let replacement = match entity.as_str() {
            "amp;" => Some('&'),
            "lt;" => Some('<'),
            "gt;" => Some('>'),
            "quot;" => Some('"'),
            "apos;" => Some('\''),
            "nbsp;" => Some('\u{00A0}'),
            _ => None,
        };

        if let Some(replacement) = replacement {
            lazy_decoded_prefix(&mut decoded, input, idx).push(replacement);
        } else if let Some(decoded) = decoded.as_mut() {
            decoded.push('&');
            decoded.push_str(&entity);
        }
    }

    decoded.ok_or(())
}

fn html_numeric_entity_decode(input: &str) -> Result<String, ()> {
    let mut decoded: Option<String> = None;
    let mut changed = false;
    let mut chars = input.char_indices().peekable();

    while let Some((idx, ch)) = chars.next() {
        if ch != '&' || !chars.peek().is_some_and(|&(_, next)| next == '#') {
            if let Some(decoded) = decoded.as_mut() {
                decoded.push(ch);
            }
            continue;
        }

        chars.next();
        let is_hex = matches!(chars.peek(), Some(&(_, 'x' | 'X')));
        if is_hex {
            chars.next();
        }

        let mut digits = String::new();
        let mut preserved_malformed = false;
        let mut consumed_terminator = false;
        while let Some(&(_, next)) = chars.peek() {
            if next == ';' {
                chars.next();
                consumed_terminator = true;
                break;
            }
            if (is_hex && next.is_ascii_hexdigit()) || (!is_hex && next.is_ascii_digit()) {
                digits.push(next);
                chars.next();
            } else {
                let out = lazy_decoded_prefix(&mut decoded, input, idx);
                out.push('&');
                out.push('#');
                if is_hex {
                    out.push('x');
                }
                out.push_str(&digits);
                out.push(next);
                chars.next();
                digits.clear();
                preserved_malformed = true;
                break;
            }
        }

        if preserved_malformed {
            continue;
        }

        if digits.is_empty() {
            if let Some(decoded) = decoded.as_mut() {
                decoded.push('&');
                decoded.push('#');
                if is_hex {
                    decoded.push('x');
                }
                if consumed_terminator {
                    decoded.push(';');
                }
            } else {
                let out = lazy_decoded_prefix(&mut decoded, input, idx);
                out.push('&');
                out.push('#');
                if is_hex {
                    out.push('x');
                }
                if consumed_terminator {
                    out.push(';');
                }
            }
            continue;
        }

        let radix = if is_hex { 16 } else { 10 };
        let code = u32::from_str_radix(&digits, radix).map_err(|_| ())?;
        let replacement = char::from_u32(code).ok_or(())?;
        lazy_decoded_prefix(&mut decoded, input, idx).push(replacement);
        changed = true;
    }

    if changed {
        decoded.ok_or(())
    } else {
        Err(())
    }
}

fn octal_escape_decode(input: &str) -> Result<String, ()> {
    let mut decoded: Option<String> = None;
    let mut chars = input.char_indices().peekable();

    while let Some((idx, ch)) = chars.next() {
        if ch != '\\' {
            if let Some(decoded) = decoded.as_mut() {
                decoded.push(ch);
            }
            continue;
        }

        let Some(&(_, next)) = chars.peek() else {
            return Err(());
        };
        if !('0'..='7').contains(&next) {
            if let Some(decoded) = decoded.as_mut() {
                decoded.push(ch);
            }
            continue;
        }

        let mut value = 0u8;
        for _ in 0..3 {
            let digit = chars.next().ok_or(())?.1;
            value = (value << 3) | digit.to_digit(8).ok_or(())? as u8;
        }
        lazy_decoded_prefix(&mut decoded, input, idx).push(char::from(value));
    }

    decoded.ok_or(())
}

fn contains_octal_escape(input: &str) -> bool {
    let bytes = input.as_bytes();
    bytes.windows(4).any(|window| {
        window[0] == b'\\'
            && (b'0'..=b'7').contains(&window[1])
            && (b'0'..=b'7').contains(&window[2])
            && (b'0'..=b'7').contains(&window[3])
    })
}

pub(crate) fn mime_encoded_word_decode(input: &str) -> Result<String, ()> {
    // `len() < 4` guards the `input[2..len-2]` slice below: the 2-byte
    // `=?` opener and `?=` closer overlap on a 3-byte input like `"=?="`
    // (both `starts_with`/`ends_with` succeed), which would make the
    // slice `[2..1]` and panic. A real MIME encoded-word is never under
    // 4 bytes, so rejecting shorter inputs loses no recall.
    if input.len() < 4 || !input.starts_with("=?") || !input.ends_with("?=") {
        return Err(());
    }
    let inner = &input[2..input.len() - 2];
    let mut parts = inner.splitn(3, '?');
    let _charset = parts.next().ok_or(())?;
    let encoding = parts.next().ok_or(())?;
    let encoded = parts.next().ok_or(())?;
    let bytes = match encoding {
        "B" | "b" => base64_decode(encoded)?,
        "Q" | "q" => mime_q_decode(encoded)?,
        _ => return Err(()),
    };
    String::from_utf8(bytes).map_err(|_| ())
}

fn mime_q_decode(input: &str) -> Result<Vec<u8>, ()> {
    let normalized = input.replace('_', " ");
    let mut bytes = Vec::with_capacity(normalized.len());
    let mut index = 0;
    let input_bytes = normalized.as_bytes();
    while index < input_bytes.len() {
        match input_bytes[index] {
            b'=' if index + 2 < input_bytes.len() => {
                let high = hex_val(input_bytes[index + 1])?;
                let low = hex_val(input_bytes[index + 2])?;
                bytes.push((high << 4) | low);
                index += 3;
            }
            byte => {
                bytes.push(byte);
                index += 1;
            }
        }
    }
    Ok(bytes)
}

fn find_mime_encoded_word_spans(text: &str) -> Vec<ExtractedValue> {
    let mut words = Vec::new();
    for line in line_views_with_offsets(text) {
        let mut offset = 0;
        while let Some(start) = line.text[offset..].find("=?") {
            let absolute_start = offset + start;
            if let Some(end) = line.text[absolute_start + 2..].find("?=") {
                let absolute_end = absolute_start + 2 + end + 2;
                words.push(ExtractedValue::new(
                    line.text[absolute_start..absolute_end].to_string(),
                    line.start + absolute_start,
                    line.start + absolute_end,
                ));
                offset = absolute_end;
            } else {
                break;
            }
        }
    }
    words
}
