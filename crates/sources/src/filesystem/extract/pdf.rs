//! Bounded PDF text extraction for filesystem entries.
//!
//! The normal text decoder must keep rejecting `%PDF-` bytes: a PDF is a
//! structured container, not a text file. This module owns the explicit PDF
//! route so `.pdf` entries are no longer silently skipped by extension while
//! malformed, encrypted, unsupported-filter, or truncated PDFs still surface a
//! source coverage gap.

use super::hexnib::hex_value;
use super::{display_path, is_symlink};
use crate::filesystem::read;
use keyhog_core::{Chunk, ChunkMetadata, SourceError};
use memchr::memmem;
use std::path::Path;

const STREAM: &[u8] = b"stream";
const ENDSTREAM: &[u8] = b"endstream";
const ENDOBJ: &[u8] = b"endobj";

const MIN_PDF_TEXT_LEN: usize = 4;
/// How far back the stream-dictionary window may reach. A stream's `<< >>`
/// object dictionary sits immediately before its `stream` keyword; 8 KiB is
/// beyond any real object dictionary. The window is additionally clamped to the
/// preceding object boundary (see `stream_dictionary_window`) so it never bleeds
/// into a prior object's dict.
const DICT_WINDOW_CAP: usize = 8192;

pub(super) fn extract_pdf_chunks(
    path: &Path,
    file_size: u64,
    live_mtime_ns: Option<u64>,
    max_size: u64,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    if is_symlink(path) {
        tracing::warn!(
            path = %path.display(),
            "refusing to open PDF at a symlink path - prevents the link-swap attack class"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        if !emit(Err(SourceError::Other(format!(
            "failed to scan PDF file '{}': refusing to open PDF at a symlink path; PDF file was not scanned",
            display_path(path)
        )))) {
            return;
        }
        return;
    }

    let bytes = match read::read_file_safe(path, file_size) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "cannot read PDF file; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            let _ = emit(Err(SourceError::Io(error))); // LAW10: loud-counted/surfaced: read failure already bumped unreadable and this terminal Err chunk is emitted before returning; consumer stop status has no later work to suppress
            return;
        }
    };
    let path_display = display_path(path);

    if !crate::magic::starts_with_pdf(&bytes) {
        emit_non_pdf_extension_fallback(bytes, path_display, live_mtime_ns, file_size, emit);
        return;
    }

    let budget = pdf_decode_budget(max_size);
    let extracted = extract_pdf_text(&bytes, budget);
    if extracted.recovered_after_error {
        let error = report_pdf_recovered_after_error(&path_display);
        if !emit(Err(error)) {
            return;
        }
    }
    if let Some(gap) = extracted.unreadable_gap {
        let error = report_pdf_unreadable_gap(&path_display, gap);
        if !emit(Err(error)) {
            return;
        }
    }
    if extracted.truncated {
        let error = report_pdf_truncation(&path_display, budget);
        if !emit(Err(error)) {
            return;
        }
    }

    let text = extracted.text.trim();
    if text.is_empty() {
        return;
    }
    if !emit(Ok(Chunk {
        data: text.to_owned().into(),
        metadata: ChunkMetadata {
            source_type: "filesystem/pdf".into(),
            path: Some(path_display.into()),
            mtime_ns: live_mtime_ns,
            size_bytes: Some(file_size),
            decoded_span: None,
            ..Default::default()
        },
    })) {
        tracing::debug!("PDF chunk consumer stopped before final chunk");
    }
}

fn report_pdf_recovered_after_error(path_display: &str) -> SourceError {
    eprintln!(
        "keyhog: WARNING: PDF extraction of {path_display} recovered decoded text and then a stream decode failed - only the recovered prefix was scanned; the rest was NOT."
    );
    let _event = crate::record_skip_event(crate::SourceSkipEvent::ArchiveTruncated);
    SourceError::Other(format!(
        "PDF extraction of '{path_display}' failed after recovering decoded text; only the recovered prefix was scanned and the remaining PDF stream bytes were not scanned"
    ))
}

fn report_pdf_unreadable_gap(path_display: &str, gap: PdfUnreadableGap) -> SourceError {
    let detail = gap.detail();
    eprintln!(
        "keyhog: WARNING: PDF extraction of {path_display} could not scan part of the PDF ({detail}); affected PDF bytes were NOT scanned."
    );
    let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
    SourceError::Other(format!(
        "PDF extraction of '{path_display}' could not scan part of the PDF ({detail}); affected PDF bytes were not scanned"
    ))
}

fn report_pdf_truncation(path_display: &str, budget: usize) -> SourceError {
    eprintln!(
        "keyhog: WARNING: PDF extraction of {path_display} hit the {budget} byte decoded-stream cap - only the truncated prefix was scanned; the rest was NOT."
    );
    let _event = crate::record_skip_event(crate::SourceSkipEvent::ArchiveTruncated);
    SourceError::Other(format!(
        "PDF extraction of '{path_display}' was truncated at the {budget}-byte decoded-stream cap; remaining decoded PDF stream bytes were not scanned"
    ))
}

fn emit_non_pdf_extension_fallback(
    bytes: Vec<u8>,
    path_display: String,
    live_mtime_ns: Option<u64>,
    file_size: u64,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    let (data, source_type) = match read::decode_text_file(&bytes) {
        Some(text) if !text.is_empty() => (text.into(), "filesystem"),
        _ => {
            let strings = crate::strings::extract_printable_strings(
                &bytes,
                crate::strings::MIN_PRINTABLE_STRING_LEN,
            );
            if strings.is_empty() {
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
                return;
            }
            (
                crate::strings::join_sensitive_strings(&strings, "\n"),
                "filesystem:binary-strings",
            )
        }
    };

    if !emit(Ok(Chunk {
        data,
        metadata: ChunkMetadata {
            source_type: source_type.into(),
            path: Some(path_display.into()),
            mtime_ns: live_mtime_ns,
            size_bytes: Some(file_size),
            decoded_span: None,
            ..Default::default()
        },
    })) {
        return;
    }
}

fn pdf_decode_budget(max_size: u64) -> usize {
    let uncapped_budget = super::UNCAPPED_ARCHIVE_BUDGET as usize;
    if max_size == 0 {
        return uncapped_budget;
    }
    let budget = max_size.saturating_mul(4);
    match usize::try_from(budget) {
        Ok(value) => value.min(uncapped_budget),
        Err(_error) => uncapped_budget,
    }
}

#[derive(Default)]
struct PdfExtract {
    text: String,
    unreadable_gap: Option<PdfUnreadableGap>,
    recovered_after_error: bool,
    truncated: bool,
}

#[derive(Clone, Copy)]
enum PdfUnreadableGap {
    Encrypted,
    MissingEndstream,
    UnsupportedFilter,
    StreamDecodeFailed,
}

impl PdfUnreadableGap {
    fn detail(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted PDF",
            Self::MissingEndstream => "stream without endstream marker",
            Self::UnsupportedFilter => "unsupported stream filter",
            Self::StreamDecodeFailed => "stream decode failed before producing text",
        }
    }
}

impl PdfExtract {
    fn record_unreadable_gap(&mut self, gap: PdfUnreadableGap) {
        if self.unreadable_gap.is_none() {
            self.unreadable_gap = Some(gap);
        }
    }
}

fn extract_pdf_text(bytes: &[u8], decoded_budget: usize) -> PdfExtract {
    let mut out = PdfExtract::default();
    if memmem::find(bytes, b"/Encrypt").is_some() {
        out.record_unreadable_gap(PdfUnreadableGap::Encrypted);
    }

    let mut ranges = Vec::new();
    let mut cursor = 0usize;
    let mut remaining_budget = decoded_budget;
    while let Some(rel) = memmem::find(&bytes[cursor..], STREAM) {
        let stream_pos = cursor + rel;
        if !is_pdf_keyword_boundary(bytes, stream_pos, STREAM.len()) {
            cursor = stream_pos + STREAM.len();
            continue;
        }

        let body_start = stream_body_start(bytes, stream_pos + STREAM.len());
        let Some(end_rel) = memmem::find(&bytes[body_start..], ENDSTREAM) else {
            out.record_unreadable_gap(PdfUnreadableGap::MissingEndstream);
            break;
        };
        let body_end = body_start + end_rel;
        ranges.push((body_start, body_end + ENDSTREAM.len()));

        if remaining_budget == 0 {
            out.truncated = true;
            cursor = body_end + ENDSTREAM.len();
            continue;
        }

        let dict = stream_dictionary_window(bytes, stream_pos);
        let stream_bytes = &bytes[body_start..body_end];
        match decode_stream(dict, stream_bytes, remaining_budget) {
            StreamDecode::Borrowed(slice, truncated) => {
                append_pdf_strings(slice, &mut out.text);
                remaining_budget = remaining_budget.saturating_sub(slice.len());
                out.truncated |= truncated;
            }
            StreamDecode::Owned(decoded, truncated, recovered_after_error) => {
                append_pdf_strings(&decoded, &mut out.text);
                remaining_budget = remaining_budget.saturating_sub(decoded.len());
                out.truncated |= truncated;
                out.recovered_after_error |= recovered_after_error;
            }
            StreamDecode::UnsupportedFilter => {
                out.record_unreadable_gap(PdfUnreadableGap::UnsupportedFilter);
            }
            StreamDecode::Unreadable => {
                out.record_unreadable_gap(PdfUnreadableGap::StreamDecodeFailed);
            }
        }
        cursor = body_end + ENDSTREAM.len();
    }

    append_pdf_strings_outside_streams(bytes, &ranges, &mut out.text);
    out
}

/// Fuzz-only byte-level entry into the hand-rolled PDF text extractor (the
/// `(...)` literal / `<...>` hex string parser, `<<>>` dict skipping, stream
/// inflate, and dictionary-window search). Compiled ONLY under `cargo fuzz`
/// (`--cfg fuzzing`), so it adds zero production API surface. Contract the
/// fuzzer enforces: for ANY input bytes and any budget, the extractor must
/// never panic, slice out of bounds, or hang (it is the reachable target when a
/// user scans an attacker-supplied `.pdf`).
#[cfg(fuzzing)]
pub fn fuzz_extract_pdf_text(bytes: &[u8], budget: usize) -> String {
    extract_pdf_text(bytes, budget).text
}

enum StreamDecode<'a> {
    Borrowed(&'a [u8], bool),
    Owned(Vec<u8>, bool, bool),
    UnsupportedFilter,
    Unreadable,
}

fn decode_stream<'a>(dict: &[u8], stream_bytes: &'a [u8], budget: usize) -> StreamDecode<'a> {
    if stream_is_image(dict) {
        return StreamDecode::Borrowed(&[], false);
    }

    let has_filter = memmem::find(dict, b"/Filter").is_some();
    let has_flate =
        memmem::find(dict, b"/FlateDecode").is_some() || memmem::find(dict, b"/Fl").is_some();

    if has_filter && !has_flate {
        return StreamDecode::UnsupportedFilter;
    }
    if has_filter {
        return inflate_pdf_stream(stream_bytes, budget);
    }

    let take = stream_bytes.len().min(budget);
    StreamDecode::Borrowed(&stream_bytes[..take], stream_bytes.len() > take)
}

fn inflate_pdf_stream(stream_bytes: &[u8], budget: usize) -> StreamDecode<'_> {
    let cap = u64::try_from(budget).unwrap_or(u64::MAX); // LAW10: unreachable on real platforms, only a wider-than-u64 usize target takes this arm, where u64::MAX is the largest stream cap the shared reader can represent.
    let decoder = flate2::read::ZlibDecoder::new(stream_bytes);
    let read = crate::capped_read::read_to_cap_preserving_error(decoder, cap, None);
    match read.error {
        None => StreamDecode::Owned(read.bytes, read.truncated, false),
        Some(_error) if !read.bytes.is_empty() => {
            StreamDecode::Owned(read.bytes, read.truncated, true)
        }
        Some(_error) => StreamDecode::Unreadable, // LAW10: loud-counted/surfaced: caller turns this stream decode failure into an unreadable source coverage gap
    }
}

fn stream_is_image(dict: &[u8]) -> bool {
    memmem::find(dict, b"/Subtype").is_some() && memmem::find(dict, b"/Image").is_some()
}

fn stream_dictionary_window(bytes: &[u8], stream_pos: usize) -> &[u8] {
    // The window must hold THIS stream's object dictionary and nothing from a
    // PREVIOUS object. A stream's dict lives between its own `obj` and `stream`,
    // always after the prior object's `endobj`/`endstream`. A fixed byte
    // lookback that crosses that boundary leaks an earlier image stream's
    // `/Subtype /Image` into a later text stream's window, so the text stream is
    // misclassified as an image and silently skipped, a recall loss with no gap
    // surfaced. Clamp the window start to the closest preceding object boundary.
    //
    // The boundary search is bounded to the cap window: a boundary farther back
    // than `DICT_WINDOW_CAP` cannot raise the floor above `cap_start` anyway, and
    // bounding it keeps this O(cap) per stream, never O(streams × n) on an
    // adversarial many-stream PDF.
    let cap_start = stream_pos.saturating_sub(DICT_WINDOW_CAP);
    let capped = &bytes[cap_start..stream_pos];
    let boundary = [
        memmem::rfind(capped, ENDOBJ).map(|idx| idx + ENDOBJ.len()),
        memmem::rfind(capped, ENDSTREAM).map(|idx| idx + ENDSTREAM.len()),
    ]
    .into_iter()
    .flatten()
    .max();
    let window_start = boundary.map_or(cap_start, |offset| cap_start + offset);
    &bytes[window_start..stream_pos]
}

fn stream_body_start(bytes: &[u8], after_stream_keyword: usize) -> usize {
    match bytes.get(after_stream_keyword) {
        Some(b'\r') => {
            if bytes.get(after_stream_keyword + 1) == Some(&b'\n') {
                after_stream_keyword + 2
            } else {
                after_stream_keyword + 1
            }
        }
        Some(b'\n') => after_stream_keyword + 1,
        _ => after_stream_keyword,
    }
}

fn is_pdf_keyword_boundary(bytes: &[u8], pos: usize, len: usize) -> bool {
    let before = pos
        .checked_sub(1)
        .and_then(|idx| bytes.get(idx))
        .copied()
        .map(is_pdf_name_byte)
        .is_some_and(|is_name| is_name);
    let after = bytes
        .get(pos + len)
        .copied()
        .map(is_pdf_name_byte)
        .is_some_and(|is_name| is_name);
    !before && !after
}

fn is_pdf_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn append_pdf_strings_outside_streams(bytes: &[u8], ranges: &[(usize, usize)], out: &mut String) {
    let mut cursor = 0usize;
    for &(start, end) in ranges {
        if start > cursor {
            append_pdf_strings(&bytes[cursor..start], out);
        }
        cursor = cursor.max(end.min(bytes.len()));
    }
    if cursor < bytes.len() {
        append_pdf_strings(&bytes[cursor..], out);
    }
}

fn append_pdf_strings(bytes: &[u8], out: &mut String) {
    let mut pos = 0usize;
    while pos < bytes.len() {
        match bytes[pos] {
            b'(' => {
                let Some(relative_close) = memchr::memchr(b')', &bytes[pos + 1..]) else {
                    break;
                };
                let next_close = pos + 1 + relative_close;
                match parse_literal_string(bytes, pos, next_close) {
                    Some((text, next)) => {
                        push_scannable_pdf_text(&text, out);
                        pos = next;
                    }
                    None => pos = next_close + 1,
                }
            }
            // `<<` opens a dictionary and `>>` closes it, neither is a hex
            // string. Skip the two-byte dict delimiter and keep scanning the
            // interior, so a literal `(...)` or hex `<...>` string that lives
            // INSIDE a dictionary is still reached. Every PDF Info-dictionary
            // metadata value (`/Author`, `/Title`, `/Keywords`, `/Producer`, …)
            // sits inside `<< >>`; treating the second `<` of `<<` as a
            // hex-string opener made `memchr(b'>')` swallow the whole dictionary
            // up to its closing `>`, silently dropping the metadata string. That
            // was a Law-10 recall hole: a credential pasted into a document's
            // properties was never scanned.
            b'<' if bytes.get(pos + 1) == Some(&b'<') => {
                pos += 2;
            }
            b'<' => {
                let Some(relative_close) = memchr::memchr(b'>', &bytes[pos + 1..]) else {
                    break;
                };
                let next_close = pos + 1 + relative_close;
                match parse_hex_string(bytes, pos, next_close) {
                    Some((text, next)) => {
                        push_scannable_pdf_text(&text, out);
                        pos = next;
                    }
                    None => pos = next_close + 1,
                }
            }
            _ => pos += 1,
        }
    }
}

fn push_scannable_pdf_text(text: &str, out: &mut String) {
    let text = text.trim();
    if text.len() < MIN_PDF_TEXT_LEN || !text.bytes().any(|b| b.is_ascii_alphanumeric()) {
        return;
    }
    if out.is_empty() {
        out.push_str(text);
    } else {
        out.push('\n');
        out.push_str(text);
    }
}

fn parse_literal_string(bytes: &[u8], start: usize, first_close: usize) -> Option<(String, usize)> {
    let mut pos = start + 1;
    let mut depth = 1usize;
    let mut out = Vec::with_capacity(first_close.saturating_sub(start + 1).min(4096));
    while pos < bytes.len() {
        match bytes[pos] {
            b'\\' => {
                pos += 1;
                if pos >= bytes.len() {
                    return None;
                }
                match bytes[pos] {
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0c),
                    b'(' | b')' | b'\\' => out.push(bytes[pos]),
                    b'\r' => {
                        if bytes.get(pos + 1) == Some(&b'\n') {
                            pos += 1;
                        }
                    }
                    b'\n' => {}
                    b'0'..=b'7' => {
                        let (value, consumed) = parse_octal_escape(bytes, pos);
                        out.push(value);
                        pos += consumed.saturating_sub(1);
                    }
                    other => out.push(other),
                }
            }
            b'(' => {
                depth += 1;
                out.push(b'(');
            }
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some((String::from_utf8_lossy(&out).into_owned(), pos + 1));
                }
                out.push(b')');
            }
            byte => out.push(byte),
        }
        pos += 1;
    }
    None
}

fn parse_octal_escape(bytes: &[u8], start: usize) -> (u8, usize) {
    let mut value = 0u16;
    let mut consumed = 0usize;
    for idx in start..(start + 3).min(bytes.len()) {
        match bytes[idx] {
            b'0'..=b'7' => {
                value = value * 8 + u16::from(bytes[idx] - b'0');
                consumed += 1;
            }
            _ => break,
        }
    }
    ((value & 0xff) as u8, consumed)
}

fn parse_hex_string(bytes: &[u8], start: usize, first_close: usize) -> Option<(String, usize)> {
    let mut pos = start + 1;
    let mut nibbles = Vec::with_capacity(first_close.saturating_sub(start + 1).min(4096));
    while pos < bytes.len() {
        let byte = bytes[pos];
        if byte == b'>' {
            if nibbles.len() % 2 == 1 {
                nibbles.push(0);
            }
            let mut decoded = Vec::with_capacity(nibbles.len() / 2);
            let mut idx = 0usize;
            while idx + 1 < nibbles.len() {
                decoded.push((nibbles[idx] << 4) | nibbles[idx + 1]);
                idx += 2;
            }
            return Some((String::from_utf8_lossy(&decoded).into_owned(), pos + 1));
        }
        if byte.is_ascii_whitespace() {
            pos += 1;
            continue;
        }
        let value = match hex_value(byte) {
            Some(value) => value,
            None => return None,
        };
        nibbles.push(value);
        pos += 1;
    }
    None
}
