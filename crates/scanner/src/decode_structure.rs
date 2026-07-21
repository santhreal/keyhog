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
//!     3000 random 24-48 byte secrets, ZERO carry any of the >= 3-byte headers at
//!     offset 0 (they are 3-8 specific bytes out of 256^k). The only 2-byte
//!     magics ('MZ'/PE, 0x1f8b/gzip) are too weak on the prefix alone, a
//!     printable 'MZ' can begin a real secret, so they are confirmed by the
//!     format's internal structure (`is_pe_image` / `is_gzip_stream`) before they
//!     may mark a candidate as binary.
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

use std::cell::RefCell;
use std::collections::HashMap;

/// Structured view of what a candidate decodes to. Carried as-is into the ML
/// feature vector once the model is retrained; consumed today through
/// [`DecodeEvidence::is_binary_payload`].
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct DecodeStructure {
    /// The candidate is a syntactically valid base64 (standard or url-safe) or
    /// hex string of a length worth decoding.
    pub(crate) decodable: bool,
    /// Number of bytes the candidate decoded to (0 when not decodable).
    pub(crate) decoded_len: usize,
    /// Fraction of decoded bytes that are printable ASCII (incl. tab/newline).
    pub(crate) printable_ratio: f32,
    /// Identified container/format from the decoded magic bytes, if any.
    pub(crate) magic: Option<&'static str>,
    /// The decoded bytes parse end-to-end as a multi-field protobuf wire stream.
    pub(crate) protobuf_wire: bool,
}

impl DecodeStructure {
    /// True when the decoded bytes are an identifiable binary asset or a
    /// serialized protobuf message - i.e. data, not a credential.
    #[must_use]
    pub(crate) fn is_binary_payload(&self) -> bool {
        self.magic.is_some() || (self.protobuf_wire && self.decoded_len >= 8)
    }
}

/// Minimum candidate length before we bother decoding. A base64 blob needs at
/// least 8 chars to carry a 4-byte magic header, and short tokens are the job
/// of the named detectors anyway.
const MIN_DECODE_LEN: usize = 16;

#[derive(Clone, Copy, Default)]
pub(crate) struct DecodeEvidence {
    structure: DecodeStructure,
    decoded_is_base64_blob: bool,
    decoded_hex_text_len: Option<usize>,
    #[cfg(any(feature = "entropy", test))]
    decoded_contains_nul_byte: bool,
    decoded_contains_placeholder: bool,
}

impl DecodeEvidence {
    #[must_use]
    pub(crate) const fn structure(self) -> DecodeStructure {
        self.structure
    }

    #[must_use]
    pub(crate) fn is_binary_payload(self) -> bool {
        self.structure.is_binary_payload()
    }

    #[must_use]
    pub(crate) const fn decoded_is_base64_blob(self) -> bool {
        self.decoded_is_base64_blob
    }

    #[must_use]
    pub(crate) const fn decoded_hex_text_len(self) -> Option<usize> {
        self.decoded_hex_text_len
    }

    #[cfg(any(feature = "entropy", test))]
    #[must_use]
    pub(crate) const fn decoded_contains_nul_byte(self) -> bool {
        self.decoded_contains_nul_byte
    }

    #[must_use]
    pub(crate) const fn decoded_contains_placeholder(self) -> bool {
        self.decoded_contains_placeholder
    }
}

thread_local! {
    static DECODE_FACTS_CACHE: RefCell<HashMap<u64, DecodeEvidence>> =
        RefCell::new(HashMap::with_capacity(256));
}

/// Unified shape-only gate for the "uniform random base64 blob" class - the
/// single parameterized definition behind every base64-protobuf-decoy gate in
/// the scanner. Reconciles two previously-divergent copies (this module's
/// penalty-path [`looks_like_uniform_base64_blob`] and the entropy-path's
/// `suppression::shape::looks_like_entropy_random_base64_blob_decoy`)
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
/// padding then qualify). The two penalty-path callers that share THIS gate are
/// [`looks_like_uniform_base64_blob`] (44..=600, diversity 32) and
/// `suppression::shape::looks_like_standard_base64_blob` (40..=80,
/// diversity 32). The emit/drop scanner paths need a stricter admit (BOTH
/// `+` AND `/`), so they share the separate [`is_byte_distribution_base64_blob`]
/// skeleton instead of this one, see that function for why the two admit
/// policies cannot be one over-parameterised gate.
#[must_use]
pub(crate) fn is_random_base64_blob(
    value: &str,
    min_len: usize,
    max_len: usize,
    min_diversity: u32,
) -> bool {
    if !(min_len..=max_len).contains(&value.len()) {
        return false;
    }
    let Some(shape) = crate::decode::standard_base64_shape(value) else {
        return false;
    };
    if !shape.has_padding && !shape.length_multiple_of_four {
        return false;
    }
    // Admit clauses:
    //   * +/  punctuation in standard base64 alphabet, OR
    //   * trailing `=` padding (length already validated as mult-of-4 path
    //     above), OR
    //   * length is mult-of-4 AND alphabet diversity >= `min_diversity`
    //     distinct alphanumeric chars (random bytes encoded; placeholders /
    //     words never reach this diversity at the band floor). A zero
    //     `min_diversity` disables this admit (punct / padding only).
    shape.has_plus
        || shape.has_slash
        || shape.has_padding
        || (min_diversity != 0
            && shape.length_multiple_of_four
            && shape.distinct_alnum >= min_diversity)
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
pub(crate) fn looks_like_uniform_base64_blob(value: &str) -> bool {
    is_random_base64_blob(value, 44, 600, 32)
}

/// Stricter sibling of [`is_random_base64_blob`] for the **emit-drop** fallback
/// paths (`suppression::shape::looks_like_entropy_random_base64_blob_decoy`
/// and `suppression::shape::looks_like_generic_random_base64_blob_decoy`).
/// Same band + padding/mult-4 + standard-base64 alphabet skeleton, but the admit
/// clause demands a genuine **byte-distribution** signal: BOTH `+` AND `/`
/// present, or trailing `=` padding with at least one of them.
///
/// Why a separate canonical instead of a parameter on [`is_random_base64_blob`]:
/// the two have *mutually exclusive* admit policies. `is_random_base64_blob`
/// powers the *penalty* path and admits on `+`-OR-`/` OR padding OR a high
/// alphanumeric-diversity wedge (tuned to slam pure-alphanumeric blobs hard).
/// This gate powers the *emit drop* and must NOT bite restricted-secret-key
/// positives that carry at most one punctuation mark, so it has no diversity
/// admit and requires BOTH punctuation marks. Real provider tokens are pure
/// base62 (no `+/`, no padding) because their length is `prefix + fixed body`,
/// never base64-of-N-random-bytes; a uniform random byte payload almost always
/// produces both `+` and `/`. Requiring both is exactly what separates the
/// protobuf-of-random-bytes decoy class from single-punct positives. Folding
/// these two would re-introduce the divergence MC-12 exists to remove, so the
/// shared *skeleton* (this function) is the single source of truth and each
/// caller composes its own band (and the generic path its entropy cutoff) on top.
#[must_use]
pub(crate) fn is_byte_distribution_base64_blob(
    value: &str,
    min_len: usize,
    max_len: usize,
) -> bool {
    if !(min_len..=max_len).contains(&value.len()) {
        return false;
    }
    let Some(shape) = crate::decode::standard_base64_shape(value) else {
        return false;
    };
    if !shape.has_padding && !shape.length_multiple_of_four {
        return false;
    }
    // Byte-distribution admit: both punctuation marks, or padded with one.
    (shape.has_plus && shape.has_slash)
        || (shape.has_padding && (shape.has_plus || shape.has_slash))
}

/// True when a base64/base64url/hex-shaped candidate decodes to ordinary
/// printable text, not a binary asset or protobuf envelope.
#[must_use]
pub(crate) fn decodes_to_printable_text(candidate: &str) -> bool {
    let evidence = evidence(candidate);
    let structure = evidence.structure();
    structure.decodable
        && structure.decoded_len >= 8
        && structure.printable_ratio >= 0.85
        && !structure.is_binary_payload()
        && !evidence.decoded_is_base64_blob()
}

/// Decode `candidate` (base64 standard, base64 url-safe, or hex) and describe
/// the resulting bytes. Returns a default (non-decodable) structure when the
/// candidate is too short or not a clean encoding.
#[must_use]
pub(crate) fn analyze(candidate: &str) -> DecodeStructure {
    evidence(candidate).structure()
}

/// Decode `candidate` once and return every decode-through predicate input
/// consumed by ML, confidence, generic fallback, and entropy fallback paths.
#[must_use]
pub(crate) fn evidence(candidate: &str) -> DecodeEvidence {
    let key = crate::util_hash::hash_fast(candidate.as_bytes());
    crate::util_hash::memoize_by_hash(
        &DECODE_FACTS_CACHE,
        key,
        crate::util_hash::DEFAULT_MAX_CACHE_ENTRIES,
        || compute_decode_facts(candidate),
    )
}

fn compute_decode_facts(candidate: &str) -> DecodeEvidence {
    let trimmed = candidate.trim();
    if trimmed.len() < MIN_DECODE_LEN {
        return DecodeEvidence::default();
    }
    let Some(bytes) = decode_candidate(trimmed) else {
        return DecodeEvidence::default();
    };
    if bytes.is_empty() {
        return DecodeEvidence::default();
    }
    let printable = bytes
        .iter()
        .filter(|&&b| (32..127).contains(&b) || matches!(b, 9 | 10 | 13))
        .count();
    let structure = DecodeStructure {
        decodable: true,
        decoded_len: bytes.len(),
        printable_ratio: printable as f32 / bytes.len() as f32,
        magic: magic_format(&bytes),
        protobuf_wire: parse_protobuf_wire(&bytes),
    };
    DecodeEvidence {
        structure,
        decoded_is_base64_blob: bytes.len() >= 32
            && bytes
                .iter()
                .all(|&b| crate::decode::is_standard_base64_byte(b)),
        // Preserve the exact decoded hex width; the owning detector TOML decides
        // which widths are key material. The decode layer must not own a second,
        // hardcoded credential-width table.
        decoded_hex_text_len: bytes
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
            .then_some(bytes.len()),
        #[cfg(any(feature = "entropy", test))]
        decoded_contains_nul_byte: bytes.contains(&0),
        decoded_contains_placeholder: crate::placeholder_words::bytes_contain_placeholder_word(
            &bytes,
        ),
    }
}

/// Decode the candidate as base64 (standard then url-safe, padded or not) or,
/// failing that, as an even-length all-hex string. Only accepts clean,
/// whole-string decodes so a stray match does not masquerade as binary.
fn decode_candidate(s: &str) -> Option<Vec<u8>> {
    // Base64 alphabets are a superset of hex's, so try the scanner's canonical
    // base64 decoder first and only fall back to hex for strings that are NOT
    // valid base64 under the same padding/alphabet contract used by decode
    // through and suppression rechecks.
    if s.as_bytes().contains(&b'_') && is_underscore_hex_candidate(s) {
        return crate::decode::hex_decode(s).ok(); // LAW10: recall-preserving trial decode; malformed underscore-hex keeps the original candidate path.
    }
    if let Ok(bytes) = crate::decode::base64_decode(s) {
        // LAW10: failed trial base64 decode falls through to hex/original candidate handling; recall is preserved.
        return Some(bytes);
    }
    if s.len() >= MIN_DECODE_LEN && s.len().is_multiple_of(2) && is_plain_hex_candidate(s) {
        return crate::decode::hex_decode(s).ok(); // LAW10: recall-preserving trial decode; malformed plain-hex keeps the original candidate path.
    }
    None
}

fn is_plain_hex_candidate(s: &str) -> bool {
    s.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_underscore_hex_candidate(s: &str) -> bool {
    let hex_len = s.bytes().filter(|&byte| byte != b'_').count();
    hex_len >= MIN_DECODE_LEN
        && hex_len.is_multiple_of(2)
        && s.bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_hexdigit())
}

/// Identify common binary container/asset formats by their leading magic
/// bytes. These headers are definitional: a stream that starts with them IS
/// that format, and no credential carries them.
fn magic_format(b: &[u8]) -> Option<&'static str> {
    // Magics of >= 3 specific bytes: over 3000 random 24-48 B secrets ZERO carry
    // these at offset 0 (>= 3 specific bytes out of 256^k), so a prefix match IS
    // the format. The 4 zlib FLG bytes below pair 0x78 with an RFC-1950 header
    // whose checksum is already valid, keeping the pair as specific as a 2-byte
    // magic can be. The genuinely weak 2-byte magics ('MZ', gzip 0x1f8b) are NOT
    // in this table: two coincidental bytes (esp. printable 'MZ') can begin a
    // real secret, so they are confirmed by internal structure below instead.
    const SIGS: &[(&[u8], &str)] = &[
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"\xff\xd8\xff", "jpeg"),
        (b"GIF87a", "gif"),
        (b"GIF89a", "gif"),
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
        (b"SQLite format 3\x00", "sqlite"),
        (b"OggS", "ogg"),
        (b"RIFF", "riff"),
        (b"\x00\x61\x73\x6d", "wasm"),
        // zlib streams: 0x78 followed by a valid-checksum FLEVEL byte.
        (b"\x78\x01", "zlib"),
        (b"\x78\x9c", "zlib"),
        (b"\x78\xda", "zlib"),
        (b"\x78\x5e", "zlib"),
    ];
    if let Some(name) = SIGS
        .iter()
        .find(|(sig, _)| b.starts_with(sig))
        .map(|(_, name)| *name)
    {
        return Some(name);
    }
    if is_pe_image(b) {
        return Some("pe");
    }
    if is_gzip_stream(b) {
        return Some("gzip");
    }
    None
}

/// A real PE image: the 'MZ' DOS header whose `e_lfanew` (u32 LE at offset 0x3C)
/// points at the `PE\0\0` NT signature inside the buffer. A bare 'MZ' prefix is
/// only ~1/65536 per candidate, and, being two printable ASCII letters, can
/// begin a genuine base64-decoded secret, so it must not drive suppression
/// alone. A short high-entropy secret cannot satisfy this structural check.
fn is_pe_image(b: &[u8]) -> bool {
    if !b.starts_with(b"MZ") || b.len() < 0x40 {
        return false;
    }
    let e_lfanew = u32::from_le_bytes([b[0x3c], b[0x3d], b[0x3e], b[0x3f]]) as usize;
    e_lfanew.checked_add(4).and_then(|end| b.get(e_lfanew..end)) == Some(b"PE\x00\x00".as_slice())
}

/// A real gzip stream: the 0x1f 0x8b magic followed by CM=8 (DEFLATE), the only
/// compression method gzip has ever used. Confirms the weak 2-byte magic with
/// the mandatory third byte so a coincidental 0x1f 0x8b pair in a secret cannot
/// mark it as binary.
fn is_gzip_stream(b: &[u8]) -> bool {
    matches!(b, [0x1f, 0x8b, 0x08, ..])
}

/// Parse `data` as a protobuf wire stream. Returns true only when the entire
/// buffer is consumed by >= 3 valid (tag, value) fields with valid wire types -
/// the profile of a real serialized message, which random bytes hit < 0.5% of
/// the time.
pub(crate) fn parse_protobuf_wire(data: &[u8]) -> bool {
    const FIXED_WIRE_WIDTHS: [usize; 8] = [0, 8, 0, 0, 0, 4, 0, 0];

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
            1 | 5 => {
                // Fixed-width value: 64-bit (wire 1) or 32-bit (wire 5). The
                // width is looked up from FIXED_WIRE_WIDTHS by the runtime wire
                // type, so both share one bounds-checked advance.
                match i.checked_add(FIXED_WIRE_WIDTHS[wire as usize]) {
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
