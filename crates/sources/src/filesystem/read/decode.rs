//! Text decoding: UTF-8 fast path, UTF-16 BOM-keyed dispatch, lossy
//! fallback, binary rejection. Used by every read path that returns a
//! `String` (buffered, mmap, windowed). Keeping these private helpers
//! together makes the binary-vs-text heuristic easy to audit and
//! changes obvious in `git diff`.

const SUSPICIOUS_CONTROL_BINARY_MIN: u64 = 4;
const BINARY_NUL_RUN: usize = 4;
const UNAMBIGUOUS_BINARY_PREFIXES: &[&[u8]] = &[
    b"%PDF-",
    b"PK\x03\x04", // ZIP / JAR / DOCX / XLSX / PPTX / APK / OOXML
    b"\x89PNG\r\n\x1a\n",
    b"\xD0\xCF\x11\xE0",   // OLE compound document (older Office)
    b"\x7fELF",            // Linux / BSD executables, .so, .o, .a
    b"\xfe\xed\xfa\xce",   // Mach-O 32-bit (macOS, iOS executables)
    b"\xfe\xed\xfa\xcf",   // Mach-O 64-bit
    b"\xcf\xfa\xed\xfe",   // Mach-O 64-bit reversed
    b"\xca\xfe\xba\xbe",   // Java .class (universal Mach-O collision)
    b"\x1f\x8b",           // gzip (.gz)
    b"\x28\xb5\x2f\xfd",   // zstd (.zst)
    b"\xfd7zXZ\x00",       // xz (.xz)
    b"7z\xbc\xaf\x27\x1c", // 7z (.7z)
    b"Rar!\x1a\x07",       // RAR
    b"GIF87a",             // GIF
    b"GIF89a",             // GIF
    b"\xff\xd8\xff",       // JPEG (any variant)
    b"\x00\x00\x01\x00",   // ICO
    b"OggS",               // Ogg container
    b"fLaC",               // FLAC
    b"\x00asm",            // WebAssembly module
    b"!<arch>\n",          // Unix `ar` archives (.a, .deb)
];

pub(crate) fn decode_text_file(bytes: &[u8]) -> Option<String> {
    // Cheap O(1) header rejects first - no full pass needed to know a PDF or
    // ZIP isn't a text file. NOTE: `has_utf16_nul_pattern` (which previously
    // co-gated this early-return) checks for the literal UTF-16 BOM, which is
    // also the correct way to START a UTF-16 text file. Including it here
    // unconditionally rejected every UTF-16-BOM file before `decode_utf16`
    // (below) ever got a chance to decode them - silently losing Windows /
    // PowerShell / .NET config files that ship as UTF-16. The BOM dispatch
    // now happens inside `decode_utf16`; only fall through to `looks_binary`
    // when decode_utf16 returns None on a NUL-rich buffer that lacks a BOM.
    if has_binary_magic(bytes) {
        return None;
    }
    // BOM-keyed UTF-16 fast path (rejects in ~6 bytes when the BOM doesn't
    // match; the streaming decode fires only on real UTF-16).
    if let Some(text) = decode_utf16(bytes) {
        return Some(text);
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes); // LAW10: no prefix/BOM to strip => value unchanged (intended), recall-safe

    // Valid-UTF-8 fast path (the common case for source trees): one SIMD
    // pass via `std::str::from_utf8` validates the whole file in zero
    // allocations. If validation succeeds AND a quick density check on the
    // header confirms it's not a 5%-controls binary that happens to be
    // valid UTF-8 (rare but possible - e.g. a UTF-8-encoded log of escape
    // sequences), we take an owned copy and return.
    //
    // Previously we ran `looks_binary` (full O(n) controls scan) AND
    // `from_utf8_lossy` (full O(n) validate + alloc) sequentially - two
    // full passes. The fused path drops one of them on valid UTF-8.
    if let Ok(s) = std::str::from_utf8(bytes) {
        // LAW10: invalid UTF-8 falls through to lossy text decode after binary checks, preserving recall.
        if looks_binary_header_check(bytes) {
            return None;
        }
        return Some(s.to_owned());
    }
    // Not strictly valid UTF-8 - may be partial corruption (the lossy path
    // is what makes us robust to minified-JS / log-tail encoding hiccups
    // and preserves recall) or actual binary. Fall back to the full
    // controls-density check before paying for the lossy copy.
    if looks_binary(bytes) {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// Owning sibling of [`decode_text_file`] for callers that already hold the
/// file's bytes in a heap-allocated `Vec<u8>` (the buffered-read path).
///
/// Decode semantics are byte-for-byte identical to `decode_text_file`; the
/// only difference is the valid-UTF-8 fast path. There, `decode_text_file`
/// is forced into `s.to_owned()` because it only borrows the bytes, which
/// copies the whole file into a fresh allocation. With an owned `Vec` we can
/// instead *move* the buffer straight into the `String` via
/// `String::from_utf8`, which reuses the existing allocation (it only
/// re-validates UTF-8, allocating nothing). That removes one full-file
/// memcpy per buffered read on the hot path. The mmap path cannot use this
/// (its backing store is a borrowed mapping, not an owned `Vec`), so it
/// keeps calling `decode_text_file`.
pub(in crate::filesystem) fn decode_text_file_owned_or_bytes(
    bytes: Vec<u8>,
) -> Result<String, Vec<u8>> {
    if has_binary_magic(&bytes) {
        return Err(bytes);
    }
    if let Some(text) = decode_utf16(&bytes) {
        return Ok(text);
    }
    let mut bytes = bytes;
    let had_utf8_bom = bytes.starts_with(&[0xEF, 0xBB, 0xBF]);
    if had_utf8_bom {
        bytes.drain(..3);
    }
    // Valid-UTF-8 fast path - identical gate to `decode_text_file`, but the
    // verified buffer is moved into the `String` (zero re-alloc) rather than
    // copied.
    match String::from_utf8(bytes) {
        Ok(s) => {
            if looks_binary_header_check(s.as_bytes()) {
                let mut bytes = s.into_bytes();
                if had_utf8_bom {
                    bytes.splice(0..0, [0xEF, 0xBB, 0xBF]);
                }
                return Err(bytes);
            }
            Ok(s)
        }
        // Not strictly valid UTF-8: recover the original bytes (no copy,
        // `into_bytes` just unwraps the buffer) and take the shared lossy /
        // binary-density fallback.
        Err(e) => {
            let bytes = e.into_bytes();
            if looks_binary(&bytes) {
                let mut bytes = bytes;
                if had_utf8_bom {
                    bytes.splice(0..0, [0xEF, 0xBB, 0xBF]);
                }
                return Err(bytes);
            }
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        }
    }
}

/// Cheap header-only binary check used after a successful strict-UTF-8
/// validation has already proven the rest is decodable. We've already
/// rejected binary-magic and UTF-16 NUL patterns at this point; all that
/// remains is the C0-controls-density heuristic. Sampling the first 4 KiB
/// catches all-control files (UTF-8 escape blobs, encoded binaries) without
/// re-scanning the whole file the way `looks_binary` does.
fn looks_binary_header_check(bytes: &[u8]) -> bool {
    let window = &bytes[..bytes.len().min(4096)];
    if window.is_empty() {
        return false;
    }
    let mut suspicious: u32 = 0;
    for &byte in window {
        if byte < 0x20 && !matches!(byte, b'\n' | b'\r' | b'\t' | 0x0C) {
            suspicious += 1;
            // Threshold matches `looks_binary` (5% suspicious bytes).
            if suspicious >= SUSPICIOUS_CONTROL_BINARY_MIN as u32
                && (suspicious as usize) * 20 > window.len()
            {
                return true;
            }
        }
    }
    false
}

pub(in crate::filesystem::read) fn looks_binary(bytes: &[u8]) -> bool {
    if has_binary_magic(bytes) || has_utf16_nul_pattern(bytes) {
        return true;
    }
    // A single NUL/control byte is not enough evidence to throw away a text
    // file. Reject obvious binary NUL runs here, then let the shared density
    // gate below make the ratio decision once it has several control bytes.
    if has_repeated_nul_run(bytes) {
        return true;
    }
    // Threshold: `suspicious * 20 > total` (i.e. >5% of the file is C0
    // controls other than the usual text whitespace/form-feed). The previous
    // implementation always ran a full O(n) `filter().count()` over every
    // byte. For source-tree scans where ~all files are obvious text, that's
    // a wasted full pass per file.
    //
    // Two-sided early exit - bail in either direction the moment the verdict
    // is provable:
    //   * As soon as at least four suspicious bytes exceed 5%, it's binary.
    //   * As soon as `(suspicious + remaining) * 20 ≤ total`, even worst-case
    //     remaining bytes can't push us past threshold → it's text.
    //
    // On a 100 KiB clean text file the loop now exits after ~5 KiB once the
    // worst-case branch concludes "no suspicious density possible." On a
    // binary blob it exits within the first few bytes once the density is
    // confirmed. Either way, the rare-but-pathological dense-clean-text
    // case still walks the whole file - same complexity bound, just a much
    // tighter constant.
    let total = bytes.len() as u64;
    if total == 0 {
        return false;
    }
    let mut suspicious: u64 = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        let is_susp = byte < 0x20 && !matches!(byte, b'\n' | b'\r' | b'\t' | 0x0C);
        if is_susp {
            suspicious += 1;
            // Confirmed binary: ratio already over threshold.
            if suspicious >= SUSPICIOUS_CONTROL_BINARY_MIN && suspicious * 20 > total {
                return true;
            }
        }
        // Confirmed text: even if every remaining byte were suspicious,
        // we couldn't reach the threshold. Sample the check once per page
        // so we don't pay the bookkeeping per byte; 4 KiB matches the
        // typical OS page size.
        if i & 0xFFF == 0xFFF {
            let scanned = (i as u64) + 1;
            let remaining = total - scanned;
            if (suspicious + remaining) * 20 <= total {
                return false;
            }
        }
    }
    suspicious >= SUSPICIOUS_CONTROL_BINARY_MIN && suspicious * 20 > total
}

pub(in crate::filesystem) fn looks_binary_prefix(bytes: &[u8]) -> bool {
    has_unambiguous_prefix_magic(bytes)
        || has_bmp_header(bytes)
        || has_pe_header(bytes)
        || has_bzip2_header(bytes)
        || has_repeated_nul_run(bytes)
}

fn has_repeated_nul_run(bytes: &[u8]) -> bool {
    memchr::memchr_iter(0, bytes).any(|index| {
        index + BINARY_NUL_RUN <= bytes.len()
            && bytes[index..index + BINARY_NUL_RUN]
                .iter()
                .all(|&byte| byte == 0)
    })
}

fn has_binary_magic(bytes: &[u8]) -> bool {
    // Common executable / archive / image / serialized-data magic bytes.
    // Each of these unambiguously identifies a binary file format whose
    // bytes cannot be a credential - short-circuiting here saves the
    // O(n) controls-density scan for files that already declare what
    // they are. Adding new magics here is cheap; removing them is the
    // dangerous direction.
    if has_bmp_header(bytes) || has_pe_header(bytes) || has_bzip2_header(bytes) {
        return true;
    }
    UNAMBIGUOUS_BINARY_PREFIXES
        .iter()
        .chain([b"\x80\x02" as &[u8]].iter()) // Python pickle protocol 2+ is full-file only.
        .any(|header| bytes.starts_with(header))
}

fn has_unambiguous_prefix_magic(bytes: &[u8]) -> bool {
    UNAMBIGUOUS_BINARY_PREFIXES
        .iter()
        .any(|header| bytes.starts_with(header))
}

fn has_bmp_header(bytes: &[u8]) -> bool {
    bytes.len() >= 14
        && bytes.starts_with(b"BM")
        && bytes[6..10] == [0, 0, 0, 0]
        && u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) >= 14
}

fn has_pe_header(bytes: &[u8]) -> bool {
    if bytes.len() < 64 || !bytes.starts_with(b"MZ") {
        return false;
    }
    let pe_offset = u32::from_le_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]) as usize;
    pe_offset >= 64
        && pe_offset
            .checked_add(4)
            .is_some_and(|end| end <= bytes.len() && &bytes[pe_offset..end] == b"PE\0\0")
}

fn has_bzip2_header(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes.starts_with(b"BZh") && matches!(bytes[3], b'1'..=b'9')
}

fn has_utf16_nul_pattern(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && (bytes[0] == 0xFF && bytes[1] == 0xFE || bytes[0] == 0xFE && bytes[1] == 0xFF)
}

pub(in crate::filesystem::read) fn decode_utf16(bytes: &[u8]) -> Option<String> {
    // BOM dispatch: try LE first, then BE; bail if neither matches.
    // The two arms can't be flattened into a single `?` because each
    // BOM also carries the endianness flag the rest of the function
    // needs - clippy::question_mark gets this wrong.
    #[allow(clippy::question_mark)]
    let (little_endian, payload) = if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        (true, rest)
    } else if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        (false, rest)
    } else {
        return None;
    };
    let chunks = payload.chunks_exact(2);
    let has_orphan_trailing_byte = !chunks.remainder().is_empty();
    if has_orphan_trailing_byte && payload.len() == 1 {
        return None;
    }
    // Stream the u16 units straight into a String through `char::decode_utf16`,
    // skipping the previous `Vec<u16>` intermediary. For a 1 MiB UTF-16 file
    // that drops a half-megabyte temp allocation and frees its cache lines
    // for the actual scan stage. ASCII-shaped UTF-16 (the common case for
    // Windows-exported logs / config) takes the BMP fast path inside
    // `char::from_u32`, no surrogate-pair fixups.
    let units = chunks.map(|chunk| {
        if little_endian {
            u16::from_le_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], chunk[1]])
        }
    });
    let mut out = String::with_capacity(payload.len() / 2);
    let mut invalid = 0usize;
    let mut total = 0usize;
    for r in char::decode_utf16(units) {
        total += 1;
        match r {
            Ok(c) => out.push(c),
            Err(_error) => {
                // Law 10: undecodable unit => U+FFFD lossy, keeps scanning the valid remainder; recall-preserving (see block comment)
                // Law 10 (no silent fallbacks): the previous `r.ok()?` returned
                // None from the WHOLE function on the first undecodable unit, so a
                // single unpaired surrogate (truncated trailing half, a binary
                // value spliced into a UTF-16 config, a mid-file corruption)
                // silently discarded every credential in the file from the text
                // path. Decode lossily instead — substitute U+FFFD and keep
                // scanning the valid remainder, matching the crate's UTF-8 lossy
                // convention (see the stdin lossy-decode path).
                invalid += 1;
                out.push('\u{FFFD}');
            }
        }
    }
    if has_orphan_trailing_byte {
        // Law 10: a single torn trailing byte in an otherwise valid UTF-16
        // file is local corruption, not evidence that the whole source file is
        // binary. Keep the decoded body and mark the orphan byte lossily.
        invalid += 1;
        total += 1;
        out.push('\u{FFFD}');
    }
    // A genuine UTF-16 text file carries at most a handful of invalid units; a
    // buffer that is *mostly* undecodable is not text at all (a binary file whose
    // first two bytes coincidentally form a BOM). Return None for those so the
    // caller routes them to `looks_binary` rather than scanning a wall of
    // replacement characters — this preserves the binary-skip precision WITHOUT
    // reintroducing the single-bad-unit whole-file drop. Threshold is generous
    // toward recall (a file is kept unless >25% of its units are undecodable).
    if total > 0 && invalid.saturating_mul(4) > total {
        return None;
    }
    Some(out)
}
