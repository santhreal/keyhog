//! Printable string extraction from binary data.
//! Shared by the filesystem source (auto-detection) and binary source (explicit).

use keyhog_core::SensitiveString;

/// ONE owner for the printable-run floor used by every `extract_printable_strings`
/// caller, binary sections/literals, web WASM extraction, and filesystem
/// archive/PDF strings. Tune the strings-scan recall floor here and nowhere else.
pub(crate) const MIN_PRINTABLE_STRING_LEN: usize = 8;

/// Extract printable ASCII strings of at least `min_len` from binary data.
///
/// Covers three encodings: contiguous printable ASCII runs, UTF-16LE "wide"
/// strings (`X 00 Y 00 …`, Windows PE / .NET, `strings -e l`), and UTF-16BE
/// (`00 X 00 Y …`, big-endian resources, `strings -e b`) (KH-1322). The ASCII
/// pass alone sees each wide char interrupted by its `0x00` and never
/// accumulates a run, so without the UTF-16 passes every wide-encoded secret
/// in a binary is silently missed.
pub(crate) fn extract_printable_strings(bytes: &[u8], min_len: usize) -> Vec<SensitiveString> {
    let mut strings = Vec::new();
    let mut current_string = String::with_capacity(64);
    for &b in bytes {
        if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
            current_string.push(b as char);
        } else {
            if current_string.len() >= min_len {
                strings.push(SensitiveString::from(current_string.as_str()));
            }
            current_string.clear();
        }
    }
    if current_string.len() >= min_len {
        strings.push(SensitiveString::from(current_string.as_str()));
    }
    let mut wide = extract_utf16_runs(bytes, min_len, true);
    wide.extend(extract_utf16_runs(bytes, min_len, false));
    wide.sort_unstable_by(|a, b| a.start.cmp(&b.start).then_with(|| b.end.cmp(&a.end)));
    let mut covered_end = 0;
    wide.retain(|run| {
        if run.start < covered_end {
            false
        } else {
            covered_end = run.end;
            true
        }
    });
    strings.extend(wide.into_iter().map(|run| run.value));
    // KH-1397: LE+BE can recover the same printable run twice.
    strings.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    strings.dedup_by(|a, b| a.as_ref() == b.as_ref());
    strings
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

struct Utf16Run {
    value: SensitiveString,
    start: usize,
    end: usize,
}

/// Recover UTF-16 printable runs and retain their byte spans. LE and BE scans
/// can otherwise report shifted suffixes for the same bytes.
fn extract_utf16_runs(bytes: &[u8], min_len: usize, little: bool) -> Vec<Utf16Run> {
    let mut runs = Vec::new();
    let mut current = String::with_capacity(64);
    let mut run_start = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        let (a, b) = (bytes[i], bytes[i + 1]);
        let (lo, hi) = if little { (a, b) } else { (b, a) };
        if hi == 0 && (lo.is_ascii_graphic() || lo == b' ' || lo == b'\t') {
            if current.is_empty() {
                run_start = i;
            }
            current.push(lo as char);
            i += 2;
        } else {
            if current.len() >= min_len {
                runs.push(Utf16Run {
                    value: SensitiveString::from(current.as_str()),
                    start: run_start,
                    end: i,
                });
            }
            current.clear();
            i += 1;
        }
    }
    if current.len() >= min_len {
        runs.push(Utf16Run {
            value: SensitiveString::from(current),
            start: run_start,
            end: i,
        });
    }
    runs
}
