use super::pipeline::{push_decoded_replacements_spliced, DECODE_REPLACEMENT_BATCH_SOURCE_BYTES};
use super::util::{resolve_escaped_codepoint, simple_control_escape, take_hex_digits};
use super::{DecodeAdmissionSketch, DecodeOutputSink, Decoder};
use keyhog_core::Chunk;

/// JSON-aware decoder that unescapes string values before scanning.
pub(super) struct JsonDecoder;

impl Decoder for JsonDecoder {
    fn name(&self) -> &'static str {
        "json"
    }

    fn admission_sketch(&self, chunk: &Chunk) -> DecodeAdmissionSketch {
        let strings = extract_escaped_json_strings(&chunk.data);
        if strings.is_empty() {
            DecodeAdmissionSketch::NONE
        } else {
            let bytes = strings
                .iter()
                .fold(0usize, |total, value| total.saturating_add(value.len()));
            DecodeAdmissionSketch::possible(DecodeAdmissionSketch::JSON, strings.len(), bytes)
        }
    }

    fn decode_chunk_into(&self, chunk: &Chunk, sink: &mut dyn DecodeOutputSink) {
        let mut current_line: Option<JsonLine> = None;
        let mut batch_start = usize::MAX;
        let mut batch_end = 0;
        let mut batch_replacements = Vec::new();

        for json_string in extract_escaped_json_strings(&chunk.data) {
            let Ok(unescaped) = json_unescape(json_string) else {
                // LAW10: recall-preserving; the original JSON text remains in the root scan.
                continue;
            };
            let value_start =
                json_string.as_ptr() as usize - chunk.data.as_bytes().as_ptr() as usize;
            let value_end = value_start + json_string.len();
            let line_start = memchr::memrchr(b'\n', &chunk.data.as_bytes()[..value_start])
                .map_or(0, |newline| newline + 1);

            if current_line
                .as_ref()
                .is_some_and(|line| line.start != line_start)
            {
                let line = current_line.take().expect("line presence checked above");
                if !stream_json_line(
                    sink,
                    chunk,
                    line,
                    &mut batch_start,
                    &mut batch_end,
                    &mut batch_replacements,
                    self.name(),
                ) {
                    return;
                }
            }

            let line = current_line.get_or_insert_with(|| {
                let line_end = memchr::memchr(b'\n', &chunk.data.as_bytes()[value_end..])
                    .map_or(chunk.data.len(), |newline| value_end + newline);
                JsonLine {
                    start: line_start,
                    end: line_end,
                    preserves_embedded_newlines: false,
                    replacements: Vec::new(),
                }
            });
            let (unescaped, preserves_embedded_newlines) =
                normalize_json_control_separators(unescaped);
            line.preserves_embedded_newlines |= preserves_embedded_newlines;
            line.replacements.push((value_start, value_end, unescaped));
        }

        if let Some(line) = current_line {
            if !stream_json_line(
                sink,
                chunk,
                line,
                &mut batch_start,
                &mut batch_end,
                &mut batch_replacements,
                self.name(),
            ) {
                return;
            }
        }
        push_decoded_replacements_spliced(
            sink,
            chunk,
            batch_start,
            batch_end,
            &mut batch_replacements,
            self.name(),
        );
    }
}

struct JsonLine {
    start: usize,
    end: usize,
    preserves_embedded_newlines: bool,
    replacements: Vec<(usize, usize, String)>,
}

fn stream_json_line(
    sink: &mut dyn DecodeOutputSink,
    chunk: &Chunk,
    mut line: JsonLine,
    batch_start: &mut usize,
    batch_end: &mut usize,
    batch_replacements: &mut Vec<(usize, usize, String)>,
    decoder_name: &str,
) -> bool {
    let exceeds_batch = *batch_start != usize::MAX
        && line.end.saturating_sub(*batch_start) > DECODE_REPLACEMENT_BATCH_SOURCE_BYTES;
    if line.preserves_embedded_newlines || exceeds_batch {
        if !push_decoded_replacements_spliced(
            sink,
            chunk,
            *batch_start,
            *batch_end,
            batch_replacements,
            decoder_name,
        ) {
            return false;
        }
        *batch_start = usize::MAX;
    }
    if line.preserves_embedded_newlines {
        return push_decoded_replacements_spliced(
            sink,
            chunk,
            line.start,
            line.end,
            &mut line.replacements,
            decoder_name,
        );
    }
    if *batch_start == usize::MAX {
        *batch_start = line.start;
    }
    *batch_end = line.end;
    batch_replacements.append(&mut line.replacements);
    true
}

fn normalize_json_control_separators(decoded: String) -> (String, bool) {
    let is_multiline_private_key =
        decoded.contains("-----BEGIN") && decoded.contains("PRIVATE KEY-----");
    if is_multiline_private_key {
        return (decoded, true);
    }
    if decoded
        .bytes()
        .any(|byte| matches!(byte, b'\n' | b'\r' | b'\t' | 0x08 | 0x0c))
    {
        (
            decoded
                .chars()
                .map(|ch| {
                    if matches!(ch, '\n' | '\r' | '\t' | '\u{8}' | '\u{c}') {
                        ' '
                    } else {
                        ch
                    }
                })
                .collect(),
            false,
        )
    } else {
        (decoded, false)
    }
}

/// Extract JSON string values that actually contain escapes.
/// Returns borrowed raw content inside quotes (including escape backslashes).
///
/// Most JSON/NDJSON fixture files are packed with plain keys and values. The
/// decoder only needs strings containing `\` escapes, so this scanner avoids
/// allocating a `String` for every ordinary JSON value and borrows only the
/// escaped spans that can produce a distinct decoded chunk.
fn extract_escaped_json_strings(text: &str) -> Vec<&str> {
    // Shortest escaped JSON string worth a distinct decoded chunk: below 4 chars
    // an unescaped body cannot carry a credential-length value.
    const MIN_ESCAPED_JSON_STRING_LEN: usize = 4;
    let mut strings = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        // memchr is byte-safe even at UTF-8 boundaries because b'"' is
        // ASCII (< 0x80) and therefore never appears inside a multi-
        // byte UTF-8 continuation. Same for b'\\' and the line
        // terminators below.
        if let Some(quote_idx) = memchr::memchr(b'"', &bytes[index..]) {
            index += quote_idx;
        } else {
            break;
        }

        // Decode JSON string *values*, not arbitrary quoted text containing a
        // JSON-compatible escape. In particular, treating
        // `api_key="left\"right"` as JSON would turn the escaped quote into a
        // real delimiter and fabricate a reportable `left` prefix. A value is
        // either the top-level string or follows JSON's value delimiters.
        let json_value_position = bytes[..index]
            .iter()
            .rposition(|byte| !byte.is_ascii_whitespace())
            .is_none_or(|previous| matches!(bytes[previous], b':' | b'[' | b','));

        // Found opening quote. Walk bytes: `"`, `\`, CR and LF are ASCII and
        // cannot appear inside a UTF-8 continuation byte, so byte scanning is
        // UTF-8 safe while avoiding per-character allocation.
        index += 1;
        let content_start = index;
        let mut saw_value_changing_escape = false;
        let mut closed = false;

        while index < bytes.len() {
            match bytes[index] {
                b'\\' => {
                    // JSON control escapes only insert whitespace/control bytes;
                    // they cannot reveal a hidden credential character. Ignore
                    // strings containing only those escapes so notebooks and
                    // generated JSON do not emit one decoded root per source
                    // line. Quotes, slashes, backslashes, and Unicode escapes
                    // can restore detector-significant bytes.
                    saw_value_changing_escape |= bytes
                        .get(index + 1)
                        .is_some_and(|escaped| matches!(escaped, b'"' | b'\\' | b'/' | b'u'));
                    // Skip the escaped byte so `\"` does not terminate this
                    // string. If the escape is truncated, the string is
                    // malformed and the outer loop will advance below.
                    index = index.saturating_add(2);
                }
                b'"' => {
                    let content_end = index;
                    index += 1;
                    closed = true;
                    if json_value_position
                        && saw_value_changing_escape
                        && content_end.saturating_sub(content_start) >= MIN_ESCAPED_JSON_STRING_LEN
                    {
                        strings.push(&text[content_start..content_end]);
                    }
                    break;
                }
                b'\n' | b'\r' => {
                    // JSON strings cannot span lines unescaped. Leave index
                    // on the terminator; the outer loop advances once below.
                    break;
                }
                _ => index += 1,
            }
        }

        if closed {
            continue;
        }

        // Either no closing quote OR we broke on a line terminator;
        // advance one byte to avoid an infinite loop on the unmatched
        // opening quote.
        index += 1;
    }

    strings
}

/// Unescape a JSON string. The input must include backslash escape sequences.
fn json_unescape(input: &str) -> Result<String, ()> {
    let mut decoded = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }

        match chars.next() {
            Some('"') => decoded.push('"'),
            Some('\\') => decoded.push('\\'),
            Some('/') => decoded.push('/'),
            Some('u') => {
                let code = take_hex_digits(&mut chars, 4)?;
                // Shared surrogate-pair resolution (see `util`): reads a
                // following `\u` low-surrogate code unit from `chars` itself.
                decoded.push(resolve_escaped_codepoint(code, &mut chars)?);
            }
            Some(escaped) => decoded.push(simple_control_escape(escaped).ok_or(())?),
            None => return Err(()),
        }
    }

    Ok(decoded)
}
