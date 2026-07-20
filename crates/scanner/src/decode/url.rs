use super::base64::base64_decode;
use super::pipeline::{
    decode_candidate_refs_exact, decode_candidate_spans_exact, push_decoded_replacements_spliced,
    with_extracted_value_spans, ExtractedValue, DECODE_REPLACEMENT_BATCH_SOURCE_BYTES,
};
use super::unicode_escape::unicode_escape_decode;
use super::util::{hex_val, lazy_decoded_prefix};
use super::{DecodeAdmissionSketch, Decoder};
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

    fn admission_sketch(&self, chunk: &Chunk) -> DecodeAdmissionSketch {
        let count = percent_escape_count(&chunk.data);
        if count == 0 {
            DecodeAdmissionSketch::NONE
        } else {
            DecodeAdmissionSketch::possible(
                DecodeAdmissionSketch::URL,
                count,
                count.saturating_mul(3),
            )
        }
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        decode_filtered_lines(chunk, contains_percent_escape, url_decode, self.name())
    }
}

impl Decoder for QuotedPrintableDecoder {
    fn name(&self) -> &'static str {
        "quoted-printable"
    }

    fn admission_sketch(&self, chunk: &Chunk) -> DecodeAdmissionSketch {
        let count = qp_escape_count(&chunk.data);
        if count == 0 {
            DecodeAdmissionSketch::NONE
        } else {
            DecodeAdmissionSketch::possible(
                DecodeAdmissionSketch::QUOTED_PRINTABLE,
                count,
                count.saturating_mul(3),
            )
        }
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

fn decode_filtered_lines<F, D>(
    chunk: &Chunk,
    filter: F,
    mut decode: D,
    decoder_name: &str,
) -> Vec<Chunk>
where
    F: Fn(&str) -> bool,
    D: FnMut(&str) -> Result<String, ()>,
{
    let mut decoded_chunks = Vec::new();
    let mut batch_start = usize::MAX;
    let mut batch_end = 0;
    let mut replacements = Vec::new();
    for line in line_views_with_offsets(&chunk.data) {
        if !filter(line.text) {
            continue;
        }
        let Ok(decoded) = decode(line.text) else {
            // LAW10: recall-preserving; a failed trial leaves the root line scanned.
            continue;
        };
        if batch_start != usize::MAX
            && line.end.saturating_sub(batch_start) > DECODE_REPLACEMENT_BATCH_SOURCE_BYTES
        {
            push_decoded_replacements_spliced(
                &mut decoded_chunks,
                chunk,
                batch_start,
                batch_end,
                &mut replacements,
                decoder_name,
            );
            batch_start = usize::MAX;
        }
        if batch_start == usize::MAX {
            batch_start = line.start;
        }
        batch_end = line.end;
        replacements.push((line.start, line.end, decoded));
    }
    push_decoded_replacements_spliced(
        &mut decoded_chunks,
        chunk,
        batch_start,
        batch_end,
        &mut replacements,
        decoder_name,
    );
    decoded_chunks
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
    qp_escape_count(s) > 0
}

fn qp_escape_count(s: &str) -> usize {
    let bytes = s.as_bytes();
    bytes
        .windows(3)
        .filter(|w| w[0] == b'=' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
        .count()
}

macro_rules! simple_decoder {
    ($decoder:ty, $name:literal, $kind:expr, $filter:expr, $decode:ident) => {
        impl Decoder for $decoder {
            fn name(&self) -> &'static str {
                $name
            }

            fn admission_sketch(&self, chunk: &Chunk) -> DecodeAdmissionSketch {
                let (mut count, mut bytes) =
                    with_extracted_value_spans(&chunk.data, |candidates| {
                        candidates
                            .iter()
                            .filter(|candidate| ($filter)(candidate.value.as_str()))
                            .fold((0usize, 0usize), |(count, bytes), candidate| {
                                (
                                    count.saturating_add(1),
                                    bytes.saturating_add(candidate.value.len()),
                                )
                            })
                    });
                let trimmed = chunk.data.trim();
                if !trimmed.is_empty() && ($filter)(trimmed) {
                    count = count.saturating_add(1);
                    bytes = bytes.saturating_add(trimmed.len());
                }
                if count == 0 {
                    DecodeAdmissionSketch::NONE
                } else {
                    DecodeAdmissionSketch::possible($kind, count, bytes)
                }
            }

            fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
                decode_filtered_lines(chunk, $filter, $decode, self.name())
            }
        }
    };
}

simple_decoder!(
    HtmlNamedEntityDecoder,
    "html-named-entity",
    DecodeAdmissionSketch::HTML_NAMED_ENTITY,
    |s: &str| s.contains('&'),
    html_named_entity_decode
);
simple_decoder!(
    HtmlNumericEntityDecoder,
    "html-numeric-entity",
    DecodeAdmissionSketch::HTML_NUMERIC_ENTITY,
    |s: &str| s.contains("&#"),
    html_numeric_entity_decode
);
simple_decoder!(
    OctalEscapeDecoder,
    "octal-escape",
    DecodeAdmissionSketch::OCTAL_ESCAPE,
    contains_octal_escape,
    octal_escape_decode
);
simple_decoder!(
    UnicodeEscapeDecoder,
    "unicode-escape",
    DecodeAdmissionSketch::UNICODE_ESCAPE,
    |s: &str| s.contains("\\u") || s.contains("\\x"),
    unicode_escape_decode
);

impl Decoder for MimeEncodedWordDecoder {
    fn name(&self) -> &'static str {
        "mime-encoded-word"
    }

    fn admission_sketch(&self, chunk: &Chunk) -> DecodeAdmissionSketch {
        let words = find_mime_encoded_word_spans(&chunk.data);
        if words.is_empty() {
            DecodeAdmissionSketch::NONE
        } else {
            let bytes = words
                .iter()
                .fold(0usize, |total, word| total.saturating_add(word.value.len()));
            DecodeAdmissionSketch::possible(
                DecodeAdmissionSketch::MIME_ENCODED_WORD,
                words.len(),
                bytes,
            )
        }
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

            // A `%` without two following hex digits, truncated at end of
            // input (`…%4`) or non-hex (`%ZZ`), is a literal byte, not the
            // start of an escape. Earlier code returned Err here, discarding
            // every escape already decoded in this candidate (all-or-nothing
            // recall loss). Treat it as literal and continue, exactly like the
            // sibling octal/HTML decoders.
            match (
                input_bytes.get(index + 1).map(|&b| hex_val(b)),
                input_bytes.get(index + 2).map(|&b| hex_val(b)),
            ) {
                (Some(Ok(high)), Some(Ok(low))) => {
                    bytes.push((high << 4) | low);
                    index += 3;
                }
                _ => {
                    bytes.push(b'%');
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

fn url_decode(input: &str) -> Result<String, ()> {
    // Bail before doing any work when there is no valid `%XX` percent-escape
    // in the candidate. The previous flow
    // copied trailing bare `%` or `%X` (one-char-short) unchanged and
    // returned the identical string - wasted decode work that the
    // `seen` dedup later dropped. Refuse the candidate earlier.
    if !contains_percent_escape(input) {
        return Err(());
    }
    percent_decode(input)
}

fn contains_percent_escape(input: &str) -> bool {
    percent_escape_count(input) > 0
}

fn percent_escape_count(input: &str) -> usize {
    input
        .as_bytes()
        .windows(3)
        .filter(|window| {
            window[0] == b'%' && hex_val(window[1]).is_ok() && hex_val(window[2]).is_ok()
        })
        .count()
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

/// Tier-B HTML named-entity → replacement decode table, the single owner
/// (`rules/html-named-entities.toml`; was an inline `match`). Keyed by the entity
/// body INCLUDING its terminating `;` (as scanned). Fails closed on an
/// invalid/empty file or a non-single-character replacement.
static HTML_NAMED_ENTITIES: std::sync::LazyLock<std::collections::HashMap<String, char>> =
    std::sync::LazyLock::new(|| {
        #[derive(serde::Deserialize)]
        struct EntitiesFile {
            entities: std::collections::BTreeMap<String, String>,
        }
        let raw = include_str!("../../../../rules/html-named-entities.toml");
        let parsed: EntitiesFile = match toml::from_str(raw) {
            Ok(parsed) => parsed,
            Err(error) => panic!(
                "rules/html-named-entities.toml is invalid: {error}. \
                 Fix the bundled Tier-B HTML named-entity table."
            ),
        };
        assert!(
            !parsed.entities.is_empty(),
            "rules/html-named-entities.toml must define at least one named entity."
        );
        parsed
            .entities
            .into_iter()
            .map(|(name, replacement)| {
                let mut chars = replacement.chars();
                let first = match chars.next() {
                    Some(first) => first,
                    None => panic!(
                        "rules/html-named-entities.toml: entity `{name}` has an empty replacement."
                    ),
                };
                assert!(
                    chars.next().is_none(),
                    "rules/html-named-entities.toml: entity `{name}` replacement must be exactly \
                     one character."
                );
                (name, first)
            })
            .collect()
    });

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

        let replacement = HTML_NAMED_ENTITIES.get(entity.as_str()).copied();

        if let Some(replacement) = replacement {
            lazy_decoded_prefix(&mut decoded, input, idx).push(replacement);
        } else if let Some(decoded) = decoded.as_mut() {
            decoded.push('&');
            decoded.push_str(&entity);
        }
    }

    decoded.ok_or(())
}

/// Longest numeric-entity digit run parsed before the entity is treated as
/// malformed. The largest valid Unicode scalar is `U+10FFFF` (6 hex or 7
/// decimal digits); ten digits allow limited leading-zero padding while
/// bounding the temporary `String`. A megabyte of leading zeros would
/// otherwise allocate unbounded memory before parsing.
pub(super) const MAX_NUMERIC_ENTITY_DIGITS: usize = 10;

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
            let is_digit =
                (is_hex && next.is_ascii_hexdigit()) || (!is_hex && next.is_ascii_digit());
            if is_digit && digits.len() < MAX_NUMERIC_ENTITY_DIGITS {
                digits.push(next);
                chars.next();
            } else {
                // Non-digit terminator OR the digit run exceeded the cap: this
                // entity is malformed / cannot be a valid scalar. Preserve the
                // opener + digits literally instead of dropping the WHOLE
                // candidate (all-or-nothing recall loss). Only consume the
                // offending byte when it is a true non-digit; an over-cap digit
                // stays for the outer loop to copy through verbatim.
                let out = lazy_decoded_prefix(&mut decoded, input, idx);
                out.push('&');
                out.push('#');
                if is_hex {
                    out.push('x');
                }
                out.push_str(&digits);
                if !is_digit {
                    out.push(next);
                    chars.next();
                }
                preserved_malformed = true;
                break;
            }
        }

        if preserved_malformed {
            continue;
        }

        // Emit the entity opener + captured digits (+ any consumed `;`) verbatim.
        // Shared by the empty-digit and out-of-range paths so the literal
        // reconstruction has one owner instead of two hand-copied branches.
        let emit_literal = |decoded: &mut Option<String>| {
            let out = lazy_decoded_prefix(decoded, input, idx);
            out.push('&');
            out.push('#');
            if is_hex {
                out.push('x');
            }
            out.push_str(&digits);
            if consumed_terminator {
                out.push(';');
            }
        };

        if digits.is_empty() {
            emit_literal(&mut decoded);
            continue;
        }

        let radix = if is_hex { 16 } else { 10 };
        // A numeric entity whose value overflows `u32` or is not a valid Unicode
        // scalar (surrogate / above U+10FFFF) is preserved literally rather than
        // dropping the whole candidate via `?`.
        let replacement = match u32::from_str_radix(&digits, radix) {
            Ok(codepoint) => char::from_u32(codepoint),
            Err(_invalid_digits) => None,
        };
        match replacement {
            Some(replacement) => {
                lazy_decoded_prefix(&mut decoded, input, idx).push(replacement);
                changed = true;
            }
            None => emit_literal(&mut decoded),
        }
    }

    if changed {
        decoded.ok_or(())
    } else {
        Err(())
    }
}

pub(crate) fn octal_escape_decode(input: &str) -> Result<String, ()> {
    let mut decoded: Option<String> = None;
    let mut chars = input.char_indices().peekable();

    while let Some((idx, ch)) = chars.next() {
        if ch != '\\' {
            if let Some(decoded) = decoded.as_mut() {
                decoded.push(ch);
            }
            continue;
        }

        // A `\` not followed by an octal digit, including a trailing `\` at end
        // of input, is a literal backslash, not the start of an escape. Earlier
        // code returned Err on a trailing `\`, discarding every octal escape
        // already decoded in this candidate (all-or-nothing recall loss); treat
        // it as a literal and keep going.
        if !matches!(chars.peek(), Some(&(_, d)) if ('0'..='7').contains(&d)) {
            if let Some(decoded) = decoded.as_mut() {
                decoded.push(ch);
            }
            continue;
        }

        // C-style octal escape: 1 to 3 octal digits, greedy. Consume octal
        // digits until a non-octal char or end of input, capping at three. A
        // short escape (`\1`, `\12`) or one truncated by a following non-octal
        // char must decode to its byte value, earlier code required EXACTLY
        // three digits and returned Err otherwise, silently dropping the whole
        // candidate (and every other escape in it) from the octal decode-through
        // path. Values above 0o377 wrap mod 256, matching the common C
        // convention for an over-long octal escape.
        let mut value = 0u8;
        for _ in 0..3 {
            match chars.peek() {
                Some(&(_, d)) if ('0'..='7').contains(&d) => {
                    value = (value << 3) | (d as u8 - b'0');
                    chars.next();
                }
                _ => break,
            }
        }
        lazy_decoded_prefix(&mut decoded, input, idx).push(char::from(value));
    }

    decoded.ok_or(())
}

fn contains_octal_escape(input: &str) -> bool {
    input
        .as_bytes()
        .windows(2)
        .any(|window| window[0] == b'\\' && (b'0'..=b'7').contains(&window[1]))
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
