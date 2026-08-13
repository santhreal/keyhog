//! Printable string extraction from binary data.
//! Shared by the filesystem source (auto-detection) and binary source (explicit).

use keyhog_core::SensitiveString;

/// ONE owner for the printable-run floor used by every `extract_printable_strings`
/// caller, binary sections/literals, web WASM extraction, and filesystem
/// archive/PDF strings. Tune the strings-scan recall floor here and nowhere else.
pub(crate) const MIN_PRINTABLE_STRING_LEN: usize = 8;
#[cfg(any(feature = "web", feature = "binary"))]
pub(crate) const BOUNDED_DERIVED_TEXT_CHUNK_BYTES: usize = 256 * 1024;

/// Separator placed between two independent printable runs recovered from the
/// same non-text input.
///
/// A bare `"\n"` was not a boundary. Detector regexes whose separator class
/// includes whitespace (`--password[=\s]+(\S{6,128})`, `key\s*[:=]\s*(...)`)
/// matched straight across it, pairing a keyword from one run with a value
/// from a run that was never adjacent to it in the file. Measured over 249 MiB
/// of system ELF binaries, every one of the nine `cli-password-flag` hits was
/// exactly that bridge (`no-ask-password` + `no-legend`, `label-password` +
/// `label-remember-password`), and none existed in the bytes.
///
/// `\0` is outside every whitespace class, so `\s` cannot cross it; the
/// newlines are outside `\S` and outside the default (non-`(?s)`) `.`, so
/// those cannot cross either. Between them no practical detector pattern
/// spans two runs. Runs themselves can never contain any of the three bytes:
/// none of them is graphic, space, or tab.
pub(crate) const RUN_SEPARATOR: &str = "\n\0\n";

/// A printable run recovered from non-text bytes, with the byte span it
/// occupied in the input.
#[derive(Clone, Copy)]
enum PrintableEncoding {
    Ascii,
    Utf16Le,
    Utf16Be,
}

#[derive(Clone, Copy)]
struct PrintableRun {
    encoding: PrintableEncoding,
    start: usize,
    end: usize,
}

/// Extract printable strings of at least `min_len` from binary data, in the
/// order they occur in `bytes`.
///
/// Covers three encodings: contiguous printable ASCII runs, UTF-16LE "wide"
/// strings (`X 00 Y 00 …`, Windows PE / .NET, `strings -e l`), and UTF-16BE
/// (`00 X 00 Y …`, big-endian resources, `strings -e b`) (KH-1322). The ASCII
/// pass alone sees each wide char interrupted by its `0x00` and never
/// accumulates a run, so without the UTF-16 passes every wide-encoded secret
/// in a binary is silently missed.
///
/// Runs come back in FILE ORDER and repeated literals are kept (KH-942). The
/// previous alphabetical sort plus whole-input value dedup made the emitted
/// text a lexicographic index of the binary, so two runs became textual
/// neighbours precisely BECAUSE they shared a prefix, which is the adjacency a
/// prefix-anchored detector regex is most likely to bridge. It also collapsed
/// every repeated literal to one occurrence, discarding the other offsets.
pub(crate) fn extract_printable_strings(bytes: &[u8], min_len: usize) -> Vec<SensitiveString> {
    extract_printable_runs(bytes, min_len)
        .into_iter()
        .map(|run| SensitiveString::from(materialize_run(bytes, run)))
        .collect()
}

/// Extract the same ordered run stream as [`extract_printable_strings`] into
/// bounded, gapless scan bodies without retaining one allocation per run.
#[cfg(any(feature = "web", feature = "binary"))]
pub(crate) fn extract_printable_string_chunks(
    bytes: &[u8],
    min_len: usize,
    chunk_bytes: usize,
) -> Vec<SensitiveString> {
    let chunk_bytes = chunk_bytes.max(1);
    let runs = extract_printable_runs(bytes, min_len);
    let mut chunks = Vec::new();
    let mut buffer = String::with_capacity(chunk_bytes);

    for (index, run) in runs.into_iter().enumerate() {
        if index > 0 {
            append_ascii_bounded(
                RUN_SEPARATOR.as_bytes(),
                chunk_bytes,
                &mut buffer,
                &mut chunks,
            );
        }
        append_run_bounded(bytes, run, chunk_bytes, &mut buffer, &mut chunks);
    }
    flush_printable_chunk(&mut buffer, chunk_bytes, &mut chunks);
    chunks
}

fn extract_printable_runs(bytes: &[u8], min_len: usize) -> Vec<PrintableRun> {
    let mut wide = extract_utf16_runs(bytes, min_len, true);
    wide.extend(extract_utf16_runs(bytes, min_len, false));
    wide.sort_unstable_by(|a, b| a.start.cmp(&b.start).then_with(|| b.end.cmp(&a.end)));
    // KH-1397: LE+BE can recover the same printable run twice, the second as a
    // shifted suffix of the first. Overlap resolution stays scoped to the wide
    // passes: an ASCII run never covers the same bytes as a wide one (a wide
    // run needs an interleaved `0x00`, which always breaks an ASCII run), so
    // widening this to all runs could only drop recall, never duplicates.
    let mut covered_end = 0;
    wide.retain(|run| {
        if run.start < covered_end {
            false
        } else {
            covered_end = run.end;
            true
        }
    });

    let mut runs = extract_ascii_runs(bytes, min_len);
    runs.extend(wide);
    runs.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| b.end.cmp(&a.end)));
    runs
}

fn extract_ascii_runs(bytes: &[u8], min_len: usize) -> Vec<PrintableRun> {
    let mut runs = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && !is_printable_ascii(bytes[index]) {
            index += 1;
        }
        let start = index;
        while index < bytes.len() && is_printable_ascii(bytes[index]) {
            index += 1;
        }
        if index - start >= min_len {
            runs.push(PrintableRun {
                encoding: PrintableEncoding::Ascii,
                start,
                end: index,
            });
        }
    }
    runs
}

#[inline]
fn is_printable_ascii(byte: u8) -> bool {
    byte.is_ascii_graphic() || byte == b' ' || byte == b'\t'
}

fn materialize_run(bytes: &[u8], run: PrintableRun) -> String {
    let capacity = match run.encoding {
        PrintableEncoding::Ascii => run.end - run.start,
        PrintableEncoding::Utf16Le | PrintableEncoding::Utf16Be => (run.end - run.start) / 2,
    };
    let mut value = String::with_capacity(capacity);
    append_run(&mut value, bytes, run);
    value
}

fn append_run(out: &mut String, bytes: &[u8], run: PrintableRun) {
    match run.encoding {
        PrintableEncoding::Ascii => {
            out.push_str(String::from_utf8_lossy(&bytes[run.start..run.end]).as_ref());
        }
        PrintableEncoding::Utf16Le | PrintableEncoding::Utf16Be => {
            let little = matches!(run.encoding, PrintableEncoding::Utf16Le);
            for pair in bytes[run.start..run.end].chunks_exact(2) {
                out.push(if little { pair[0] } else { pair[1] } as char);
            }
        }
    }
}

#[cfg(any(feature = "web", feature = "binary"))]
fn append_run_bounded(
    bytes: &[u8],
    run: PrintableRun,
    chunk_bytes: usize,
    buffer: &mut String,
    chunks: &mut Vec<SensitiveString>,
) {
    match run.encoding {
        PrintableEncoding::Ascii => {
            append_ascii_bounded(&bytes[run.start..run.end], chunk_bytes, buffer, chunks)
        }
        PrintableEncoding::Utf16Le | PrintableEncoding::Utf16Be => {
            let little = matches!(run.encoding, PrintableEncoding::Utf16Le);
            for pair in bytes[run.start..run.end].chunks_exact(2) {
                if buffer.len() == chunk_bytes {
                    flush_printable_chunk(buffer, chunk_bytes, chunks);
                }
                buffer.push(if little { pair[0] } else { pair[1] } as char);
            }
        }
    }
}

#[cfg(any(feature = "web", feature = "binary"))]
fn append_ascii_bounded(
    mut bytes: &[u8],
    chunk_bytes: usize,
    buffer: &mut String,
    chunks: &mut Vec<SensitiveString>,
) {
    while !bytes.is_empty() {
        if buffer.len() == chunk_bytes {
            flush_printable_chunk(buffer, chunk_bytes, chunks);
        }
        let take = bytes.len().min(chunk_bytes - buffer.len());
        buffer.push_str(String::from_utf8_lossy(&bytes[..take]).as_ref());
        bytes = &bytes[take..];
    }
}

#[cfg(any(feature = "web", feature = "binary"))]
fn flush_printable_chunk(
    buffer: &mut String,
    chunk_bytes: usize,
    chunks: &mut Vec<SensitiveString>,
) {
    if buffer.is_empty() {
        return;
    }
    chunks.push(SensitiveString::from(std::mem::replace(
        buffer,
        String::with_capacity(chunk_bytes),
    )));
}
/// Join printable runs recovered from one non-text input into one scannable
/// body. The SINGLE owner of that separator choice; see [`RUN_SEPARATOR`] for
/// why it is not `"\n"`.
pub(crate) fn join_printable_runs(parts: &[SensitiveString]) -> SensitiveString {
    join_sensitive_strings(parts, RUN_SEPARATOR)
}

pub(crate) fn join_sensitive_strings(parts: &[SensitiveString], sep: &str) -> SensitiveString {
    let mut joined = String::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            joined.push_str(sep);
        }
        joined.push_str(part.as_ref());
    }
    SensitiveString::from(joined)
}

/// Recover UTF-16 printable runs and retain their byte spans. LE and BE scans
/// can otherwise report shifted suffixes for the same bytes.
fn extract_utf16_runs(bytes: &[u8], min_len: usize, little: bool) -> Vec<PrintableRun> {
    let mut runs = Vec::new();
    let mut run_len = 0;
    let mut run_start = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        let (a, b) = (bytes[i], bytes[i + 1]);
        let (lo, hi) = if little { (a, b) } else { (b, a) };
        if hi == 0 && is_printable_ascii(lo) {
            if run_len == 0 {
                run_start = i;
            }
            run_len += 1;
            i += 2;
        } else {
            if run_len >= min_len {
                runs.push(PrintableRun {
                    encoding: if little {
                        PrintableEncoding::Utf16Le
                    } else {
                        PrintableEncoding::Utf16Be
                    },
                    start: run_start,
                    end: i,
                });
            }
            run_len = 0;
            i += 1;
        }
    }
    if run_len >= min_len {
        runs.push(PrintableRun {
            encoding: if little {
                PrintableEncoding::Utf16Le
            } else {
                PrintableEncoding::Utf16Be
            },
            start: run_start,
            end: i,
        });
    }
    runs
}
