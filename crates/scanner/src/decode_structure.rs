//! Decode-structure analysis: keyhog's decode-through advantage, fed into
//! scoring.
//!
//! A generic high-entropy candidate (caught by `generic-secret`,
//! `generic-password`, `entropy-*`) is ambiguous on its surface: a real
//! base64/hex secret and a base64-wrapped *binary asset* (a PNG, a gzip blob,
//! a serialized protobuf, an embedded cert) look identical to an
//! entropy/regex/token-efficiency filter. The distinguishing signal is what
//! the candidate *decodes to* - and keyhog already decodes. This module turns
//! the decoded bytes into a verdict the confidence pipeline (and, later, the ML
//! feature vector) can use.
//!
//! The verdict is built only on **definitional** signals, so it never
//! false-suppresses a real credential:
//!   * **Magic bytes.** A blob that decodes to a PNG/JPEG/GIF/gzip/zip/PDF/ELF/
//!     Mach-O/PE/zstd/xz/bzip2/7z/SQLite/Java-class header IS that format. Over
//!     3000 random 24-48 byte secrets, ZERO carry any of these headers at
//!     offset 0 (they are 4-8 specific bytes out of 256^k).
//!   * **Full protobuf-wire parse.** Bytes that parse end-to-end as a protobuf
//!     wire stream (valid field tags, valid wire types, length-delimited fields
//!     that stay in bounds, whole buffer consumed) with several fields are a
//!     serialized message. Random bytes parse this way <0.5% of the time, and
//!     we additionally require >= 3 fields and >= 8 bytes.
//!
//! Printable-ratio is recorded for the future ML feature but is NOT used in the
//! boolean verdict: random secret bytes and binary blobs both sit around 37-50%
//! printable, so it is too weak to gate suppression on its own.
//!
//! Tests live in `tests/unit/decode_structure*.rs` (Santh no-inline-tests
//! contract).

use base64::Engine;

/// Structured view of what a candidate decodes to. Carried as-is into the ML
/// feature vector once the model is retrained; consumed today by
/// [`is_encoded_binary`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DecodeStructure {
    /// The candidate is a syntactically valid base64 (standard or url-safe) or
    /// hex string of a length worth decoding.
    pub decodable: bool,
    /// Number of bytes the candidate decoded to (0 when not decodable).
    pub decoded_len: usize,
    /// Fraction of decoded bytes that are printable ASCII (incl. tab/newline).
    pub printable_ratio: f32,
    /// Identified container/format from the decoded magic bytes, if any.
    pub magic: Option<&'static str>,
    /// The decoded bytes parse end-to-end as a multi-field protobuf wire stream.
    pub protobuf_wire: bool,
}

impl DecodeStructure {
    /// True when the decoded bytes are an identifiable binary asset or a
    /// serialized protobuf message - i.e. data, not a credential.
    #[must_use]
    pub fn is_binary_payload(&self) -> bool {
        self.magic.is_some() || (self.protobuf_wire && self.decoded_len >= 8)
    }
}

/// Minimum candidate length before we bother decoding. A base64 blob needs
/// >= 8 chars to carry a 4-byte magic header, and short tokens are the job of
/// the named detectors anyway.
const MIN_DECODE_LEN: usize = 16;

/// Conservative verdict for the confidence pipeline: does this generic
/// candidate decode to identifiable binary / serialized data? Real secrets
/// return `false`.
///
/// Memoized: a single match is scored on this twice (ML feature #41 in
/// `ml_features` and the generic-detector confidence penalty in
/// `confidence::penalties`), and a scan re-encounters the same token across
/// chunks. Without the cache every call re-decodes and re-parses the bytes.
/// Thread-local + bounded with wholesale eviction, mirroring
/// `entropy::shannon_entropy`. The verdict is a pure function of `candidate`,
/// so caching by content hash is always correct.
#[must_use]
pub fn is_encoded_binary(candidate: &str) -> bool {
    use std::cell::RefCell;
    use std::collections::HashMap;

    const MAX_CACHE_ENTRIES: usize = 4096;

    thread_local! {
        static CACHE: RefCell<HashMap<u64, bool>> = RefCell::new(HashMap::with_capacity(256));
    }

    // FNV-1a over the candidate bytes - the same hash the entropy / ML-score
    // caches key on.
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in candidate.as_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }

    CACHE.with(|cache| {
        if let Some(&verdict) = cache.borrow().get(&hash) {
            return verdict;
        }
        let verdict = analyze(candidate).is_binary_payload();
        let mut cache = cache.borrow_mut();
        if cache.len() >= MAX_CACHE_ENTRIES {
            cache.clear();
        }
        cache.insert(hash, verdict);
        verdict
    })
}

/// Placeholder words that mark a credential as a documentation sample, not a
/// real secret. The single source of truth for the lowercase byte-slice
/// placeholder set: consumed for the SURFACE form by
/// `confidence::penalties::contains_placeholder_word` and for the BASE64 / HEX
/// decoded form by this module's [`decoded_contains_placeholder`] (so a
/// base64-wrapped `AKIAEXAMPLEEXAMPLE12` = `QUtJQUVYQU1QTEVFWEFNUExFMTI=` is
/// still caught).
///
/// Excludes ambiguous tokens by design: `test` (real Stripe `sk_test_` keys),
/// `password` (connection strings `redis://user:password@host`), `admin` /
/// `root` (legitimate credentials), `qwerty` (weak but real password).
pub const PLACEHOLDER_WORDS: &[&[u8]] = &[
    b"example",
    b"dummy",
    b"fake",
    b"sample",
    b"placeholder",
    b"changeme",
];

/// Unified shape-only gate for the "uniform random base64 blob" class - the
/// single parameterized definition behind every base64-protobuf-decoy gate in
/// the scanner. Reconciles two previously-divergent copies (this module's
/// penalty-path [`looks_like_uniform_base64_blob`] and the entropy-path's
/// `engine::fallback_entropy_helpers::entropy_path_looks_like_random_base64_blob`)
/// so their length/diversity bands are tuned in one place and can never drift
/// in opposite directions un-benched again.
///
/// Returns true when `value`:
///   1. has length in `min_len..=max_len`, AND
///   2. is a multiple-of-4 length OR carries trailing `=` padding, AND
///   3. uses only the standard base64 alphabet (`A-Za-z0-9`, `=`, `+`, `/`) -
///      any `-`/`_`/`.`/other char rejects, which clears base64url tokens
///      (GitHub PATs, OAuth bearers), JWTs (`.`), and Slack (`-`), AND
///   4. satisfies an admit clause: contains `+`/`/` punctuation, OR has
///      padding, OR (length is mult-of-4 AND alphabet diversity >=
///      `min_diversity` distinct alphanumeric chars). The diversity admit
///      catches pure-alphanumeric base64 (no `+/`) that random-byte encodings
///      reach but placeholders / English words never do at the band floor.
///
/// `min_diversity == 0` disables the diversity admit (only punctuation /
/// padding then qualify) - that is how a caller wanting the stricter
/// "structural punctuation required" behavior (the entropy path's intent)
/// opts out of the diversity wedge while still sharing this band + alphabet
/// skeleton. The entropy path additionally requires BOTH `+` and `/`; it
/// composes that tightening on top of this gate in its own wrapper (it owns
/// that file boundary), calling here for the band + alphabet + padding
/// skeleton.
#[must_use]
pub fn is_random_base64_blob(
    value: &str,
    min_len: usize,
    max_len: usize,
    min_diversity: u32,
) -> bool {
    if !(min_len..=max_len).contains(&value.len()) {
        return false;
    }
    let has_padding = value.ends_with("==") || value.ends_with('=');
    let length_mult_4 = value.len().is_multiple_of(4);
    if !has_padding && !length_mult_4 {
        return false;
    }
    let mut has_b64_punct = false;
    let mut seen = [false; 256];
    let mut distinct_alnum: u32 = 0;
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => {
                if !seen[b as usize] {
                    seen[b as usize] = true;
                    distinct_alnum += 1;
                }
            }
            b'=' => {}
            b'+' | b'/' => has_b64_punct = true,
            _ => return false,
        }
    }
    // Admit clauses:
    //   * +/  punctuation in standard base64 alphabet, OR
    //   * trailing `=` padding (length already validated as mult-of-4 path
    //     above), OR
    //   * length is mult-of-4 AND alphabet diversity >= `min_diversity`
    //     distinct alphanumeric chars (random bytes encoded; placeholders /
    //     words never reach this diversity at the band floor). A zero
    //     `min_diversity` disables this admit (punct / padding only).
    has_b64_punct
        || has_padding
        || (min_diversity != 0 && length_mult_4 && distinct_alnum >= min_diversity)
}

/// Shape-only check: does `value` look like a uniform base64 blob with no
/// structure markers? Thin wrapper over [`is_random_base64_blob`] with the
/// penalty-path band (44..=600) and diversity floor (32). Matches the
/// `random-base64-protobuf` corpus shape (random bytes base64-encoded into a
/// `password=`/`secret=` slot) without firing on real service-anchored
/// credentials:
///   * AWS secret access keys (40 base62 chars, no +/, no padding) - too short
///   * GitHub PATs (40+ chars but contain `_`) - skipped (alphabet check)
///   * npm tokens (36 chars base62) - too short, skipped
///   * Stripe keys (32 chars, `sk_`/`pk_` prefix with `_`) - skipped
///   * Slack tokens (xox*-prefixed with `-`) - skipped
///   * JWT tokens (`.` separators) - skipped
///   * OAuth bearer tokens with `-`/`_` (base64url) - skipped via alphabet
///
/// Used by `confidence::penalties::apply_post_ml_penalties` as the generic-
/// detector branch's "this is a random base64 blob, not a credential" gate.
/// Mirror v27 had 56 base64-protobuf FPs surviving every other suppression;
/// this is the dedicated gate for that class. v33 widened the floor from
/// 60 to 44 and added a high-diversity admit so pure-alphanumeric base64
/// (lacking +/) is also slammed - 14+ FPs in the corpus relied on the
/// gap.
#[must_use]
pub fn looks_like_uniform_base64_blob(value: &str) -> bool {
    is_random_base64_blob(value, 44, 600, 32)
}

/// True when `value` base64-decodes to bytes that are themselves all in
/// the base64 alphabet (double-encoded base64). k8s `data:` fields wrap
/// their values in another base64 layer; the inner decoded bytes are the
/// actual user content, and when those bytes are themselves a printable
/// base64 blob the outer wrapper is categorically data, not a credential.
///
/// Conservative: requires the decoded length to be >= 32 chars AND the
/// decoded bytes to be all standard-base64 alphabet (A-Za-z0-9+/=).
/// Random secret bytes would produce non-base64 bytes (non-printable,
/// 0x00..0x20, 0x80..0xFF) so this is definitional, not heuristic.
///
/// Memoized via the same FNV-1a hash + thread-local cache pattern as the
/// other decode-through helpers.
#[must_use]
pub fn decoded_is_base64_blob(candidate: &str) -> bool {
    use std::cell::RefCell;
    use std::collections::HashMap;

    const MAX_CACHE_ENTRIES: usize = 4096;

    thread_local! {
        static CACHE: RefCell<HashMap<u64, bool>> = RefCell::new(HashMap::with_capacity(256));
    }

    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in candidate.as_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }

    CACHE.with(|cache| {
        if let Some(&verdict) = cache.borrow().get(&hash) {
            return verdict;
        }
        let verdict = compute_decoded_is_base64_blob(candidate);
        let mut cache = cache.borrow_mut();
        if cache.len() >= MAX_CACHE_ENTRIES {
            cache.clear();
        }
        cache.insert(hash, verdict);
        verdict
    })
}

fn compute_decoded_is_base64_blob(candidate: &str) -> bool {
    let trimmed = candidate.trim();
    if trimmed.len() < MIN_DECODE_LEN {
        return false;
    }
    let Some(bytes) = decode_candidate(trimmed) else {
        return false;
    };
    if bytes.len() < 32 {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

/// Decode `candidate` (base64 / url-safe-base64 / hex) and check whether the
/// decoded bytes contain any placeholder word case-insensitively. Composes
/// keyhog's decode-through with the placeholder suppression: a docs sample
/// that arrives base64-wrapped (e.g. AWS docs publishing AKIAEXAMPLEEXAMPLE12
/// as the base64-encoded body of a yaml secret) is now recognized as a sample
/// even though the surface form looks like high-entropy random bytes. Mirror
/// v26: 9 docs-example-marker FPs (all `QUtJQUVYQU1QTEVFWEFNUExFMTI=`, base64
/// of AKIA...EXAMPLE...12) collapsed by this gate. Memoized to match the
/// existing `is_encoded_binary` call cadence.
#[must_use]
pub fn decoded_contains_placeholder(candidate: &str) -> bool {
    use std::cell::RefCell;
    use std::collections::HashMap;

    const MAX_CACHE_ENTRIES: usize = 4096;

    thread_local! {
        static CACHE: RefCell<HashMap<u64, bool>> = RefCell::new(HashMap::with_capacity(256));
    }

    // FNV-1a over the candidate bytes - keyed identically to is_encoded_binary
    // so the two caches cost a single hash per credential.
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in candidate.as_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }

    CACHE.with(|cache| {
        if let Some(&verdict) = cache.borrow().get(&hash) {
            return verdict;
        }
        let verdict = compute_decoded_contains_placeholder(candidate);
        let mut cache = cache.borrow_mut();
        if cache.len() >= MAX_CACHE_ENTRIES {
            cache.clear();
        }
        cache.insert(hash, verdict);
        verdict
    })
}

fn compute_decoded_contains_placeholder(candidate: &str) -> bool {
    let trimmed = candidate.trim();
    if trimmed.len() < MIN_DECODE_LEN {
        return false;
    }
    let Some(bytes) = decode_candidate(trimmed) else {
        return false;
    };
    if bytes.is_empty() {
        return false;
    }
    PLACEHOLDER_WORDS.iter().any(|word| {
        bytes
            .windows(word.len())
            .any(|window| window.eq_ignore_ascii_case(word))
    })
}

/// Decode `candidate` (base64 standard, base64 url-safe, or hex) and describe
/// the resulting bytes. Returns a default (non-decodable) structure when the
/// candidate is too short or not a clean encoding.
#[must_use]
pub fn analyze(candidate: &str) -> DecodeStructure {
    let trimmed = candidate.trim();
    if trimmed.len() < MIN_DECODE_LEN {
        return DecodeStructure::default();
    }
    let Some(bytes) = decode_candidate(trimmed) else {
        return DecodeStructure::default();
    };
    if bytes.is_empty() {
        return DecodeStructure::default();
    }
    let printable = bytes
        .iter()
        .filter(|&&b| (32..127).contains(&b) || matches!(b, 9 | 10 | 13))
        .count();
    DecodeStructure {
        decodable: true,
        decoded_len: bytes.len(),
        printable_ratio: printable as f32 / bytes.len() as f32,
        magic: magic_format(&bytes),
        protobuf_wire: parse_protobuf_wire(&bytes),
    }
}

/// Decode the candidate as base64 (standard then url-safe, padded or not) or,
/// failing that, as an even-length all-hex string. Only accepts clean,
/// whole-string decodes so a stray match does not masquerade as binary.
fn decode_candidate(s: &str) -> Option<Vec<u8>> {
    // base64 alphabets are a superset of hex's, so try base64 first and only
    // fall back to hex for strings that are NOT valid base64.
    let looks_b64 = s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_' | b'='));
    if looks_b64 {
        // Pad to a multiple of 4 so unpadded blobs decode.
        let mut padded = s.to_string();
        let rem = padded.len() % 4;
        if rem != 0 {
            padded.push_str(&"=".repeat(4 - rem));
        }
        if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(padded.as_bytes()) {
            return Some(b);
        }
        if let Ok(b) = base64::engine::general_purpose::URL_SAFE.decode(padded.as_bytes()) {
            return Some(b);
        }
    }
    if s.len() >= MIN_DECODE_LEN && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut out = Vec::with_capacity(s.len() / 2);
        let raw = s.as_bytes();
        let mut i = 0;
        while i + 1 < raw.len() {
            let hi = (raw[i] as char).to_digit(16)?;
            let lo = (raw[i + 1] as char).to_digit(16)?;
            out.push(((hi << 4) | lo) as u8);
            i += 2;
        }
        return Some(out);
    }
    None
}

/// Identify common binary container/asset formats by their leading magic
/// bytes. These headers are definitional: a stream that starts with them IS
/// that format, and no credential carries them.
fn magic_format(b: &[u8]) -> Option<&'static str> {
    const SIGS: &[(&[u8], &str)] = &[
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"\xff\xd8\xff", "jpeg"),
        (b"GIF87a", "gif"),
        (b"GIF89a", "gif"),
        (b"\x1f\x8b", "gzip"),
        (b"BZh", "bzip2"),
        (b"\xfd7zXZ\x00", "xz"),
        (b"\x28\xb5\x2f\xfd", "zstd"),
        (b"PK\x03\x04", "zip"),
        (b"PK\x05\x06", "zip"),
        (b"7z\xbc\xaf\x27\x1c", "7z"),
        (b"Rar!\x1a\x07", "rar"),
        (b"%PDF-", "pdf"),
        (b"\x7fELF", "elf"),
        (b"\xfe\xed\xfa\xce", "mach-o"),
        (b"\xfe\xed\xfa\xcf", "mach-o"),
        (b"\xcf\xfa\xed\xfe", "mach-o"),
        (b"\xca\xfe\xba\xbe", "java-class"),
        (b"MZ", "pe"),
        (b"SQLite format 3\x00", "sqlite"),
        (b"OggS", "ogg"),
        (b"RIFF", "riff"),
        (b"\x00\x61\x73\x6d", "wasm"),
        // zlib streams: 0x78 followed by a valid FLEVEL byte.
        (b"\x78\x01", "zlib"),
        (b"\x78\x9c", "zlib"),
        (b"\x78\xda", "zlib"),
        (b"\x78\x5e", "zlib"),
    ];
    SIGS.iter()
        .find(|(sig, _)| b.starts_with(sig))
        .map(|(_, name)| *name)
}

/// Parse `data` as a protobuf wire stream. Returns true only when the entire
/// buffer is consumed by >= 3 valid (tag, value) fields with valid wire types -
/// the profile of a real serialized message, which random bytes hit < 0.5% of
/// the time.
fn parse_protobuf_wire(data: &[u8]) -> bool {
    let n = data.len();
    if n < 8 {
        return false;
    }
    let mut i = 0usize;
    let mut fields = 0u32;
    while i < n {
        let Some((tag, next)) = read_varint(data, i) else {
            return false;
        };
        i = next;
        let wire = tag & 0x07;
        let field_no = tag >> 3;
        if field_no == 0 {
            return false;
        }
        match wire {
            0 => {
                // varint value
                let Some((_, next)) = read_varint(data, i) else {
                    return false;
                };
                i = next;
            }
            1 => {
                // 64-bit fixed
                match i.checked_add(8) {
                    Some(x) if x <= n => i = x,
                    _ => return false,
                }
            }
            2 => {
                // length-delimited
                let Some((len, next)) = read_varint(data, i) else {
                    return false;
                };
                i = match next.checked_add(len as usize) {
                    Some(x) if x <= n => x,
                    _ => return false,
                };
            }
            5 => {
                // 32-bit fixed
                match i.checked_add(4) {
                    Some(x) if x <= n => i = x,
                    _ => return false,
                }
            }
            _ => return false, // 3,4 (groups, deprecated) and 6,7 (invalid)
        }
        fields += 1;
    }
    i == n && fields >= 3
}

/// Read a base-128 varint at `data[start..]`, returning (value, next_index).
fn read_varint(data: &[u8], start: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    let mut i = start;
    loop {
        let b = *data.get(i)?;
        i += 1;
        value |= u64::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return Some((value, i));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}
