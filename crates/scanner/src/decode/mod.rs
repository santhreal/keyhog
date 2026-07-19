//! Decode-through scanning: decode encoded strings before pattern matching.
//!
//! Catches secrets hidden behind encoding layers - Kubernetes manifests,
//! CI/CD configs, URL-escaped payloads, string escapes, and hex-encoded
//! credentials.

mod base64;
pub(crate) mod caesar;
pub(crate) mod hex;
pub(crate) mod inflate;
#[cfg(feature = "decode")]
mod javascript_static;
mod json;
mod limits;
mod pipeline;
pub(crate) mod policy;
pub(crate) mod reverse;
mod unicode_escape;
mod url;
pub(crate) mod util;

pub use base64::{base64_decode, find_base64_strings, z85_decode};
// `is_base64_candidate_byte` is the single canonical base64/url-safe alphabet
// predicate; it is `pub` (not `pub(crate)`) because `keyhog-cli`'s autoroute
// decode-density scanner (`orchestrator::dispatch::backend::workload`) is a
// cross-crate consumer that must route through this one owner rather than
// re-inline the byte set. The remaining three stay crate-internal.
pub use base64::is_base64_candidate_byte;
pub(crate) use base64::{
    contains_non_padding_equals, is_standard_base64_byte, standard_base64_shape,
};
pub use hex::{find_hex_strings, hex_decode};
pub use pipeline::register_decoder;
pub(crate) use pipeline::{
    bytecount_newlines, decoder_profile_dump, decoder_profile_reset, extract_profile_dump,
    extract_profile_reset, splice_decoded_payload_at, with_extracted_value_spans,
};
#[cfg(feature = "decode")]
pub(crate) use pipeline::{decoder_admission, default_decoder_names};
#[cfg(test)]
pub(crate) use pipeline::{register_thread_decoder, ScopedDecoderRegistration};
pub(crate) use util::take_hex_digits;

use keyhog_core::Chunk;

pub(crate) fn decode_chunk_with_policy(
    chunk: &Chunk,
    policy: &policy::CompiledDecodeTransformPolicy,
    max_depth: usize,
    validate: bool,
    deadline: Option<std::time::Instant>,
    screen: Option<&crate::alphabet_filter::AlphabetScreen>,
) -> Vec<Chunk> {
    pipeline::decode_chunk_with_policy(chunk, policy, max_depth, validate, deadline, screen)
}

/// Direct primitive compatibility for the public testing facade. Product
/// scans always call `decode_chunk_with_policy` with their active detector
/// corpus.
pub(crate) fn decode_chunk(
    chunk: &Chunk,
    max_depth: usize,
    validate: bool,
    deadline: Option<std::time::Instant>,
    screen: Option<&crate::alphabet_filter::AlphabetScreen>,
) -> Vec<Chunk> {
    decode_chunk_with_policy(
        chunk,
        policy::bundled_compat_policy(),
        max_depth,
        validate,
        deadline,
        screen,
    )
}

pub(crate) fn unicode_escape_decode(input: &str) -> Result<String, ()> {
    unicode_escape::unicode_escape_decode(input)
}

#[cfg(feature = "decode")]
pub(crate) fn quoted_printable_decode(input: &str) -> Result<String, ()> {
    url::quoted_printable_decode(input)
}

#[cfg(feature = "decode")]
pub(crate) fn mime_encoded_word_decode(input: &str) -> Result<String, ()> {
    url::mime_encoded_word_decode(input)
}

#[cfg(feature = "decode")]
pub(crate) fn octal_escape_decode(input: &str) -> Result<String, ()> {
    url::octal_escape_decode(input)
}

pub(crate) fn extracted_value_strings_for_test(text: &str) -> Vec<String> {
    pipeline::with_extracted_value_spans(text, |values| {
        values.iter().map(|value| value.value.clone()).collect()
    })
}

#[cfg(feature = "decode")]
fn valid_html_numeric_entity_len(data: &[u8]) -> Option<usize> {
    if !data.starts_with(b"&#") {
        return None;
    }

    let mut index = 2usize;
    let radix = if matches!(data.get(index), Some(b'x' | b'X')) {
        index += 1;
        16u32
    } else {
        10u32
    };
    let digits_start = index;
    let mut codepoint = 0u32;
    while index < data.len() && index - digits_start < url::MAX_NUMERIC_ENTITY_DIGITS {
        let digit = match data[index] {
            b'0'..=b'9' => u32::from(data[index] - b'0'),
            b'a'..=b'f' if radix == 16 => u32::from(data[index] - b'a') + 10,
            b'A'..=b'F' if radix == 16 => u32::from(data[index] - b'A') + 10,
            _ => break,
        };
        codepoint = codepoint.checked_mul(radix)?.checked_add(digit)?;
        index += 1;
    }

    if index == digits_start || data.get(index) != Some(&b';') {
        return None;
    }
    char::from_u32(codepoint)?;
    Some(index + 1)
}

/// Cheap O(n), allocation-free gate: does `data` contain an encoded shape long
/// enough to plausibly hide a credential?
///
/// The direct-match prefilters (`AlphabetScreen`, the bigram bloom) reject a
/// chunk that carries none of any detector's literal bytes/bigrams - which is
/// EXACTLY the shape of a fully-encoded secret, whose plaintext keyword/prefix
/// only appears AFTER decoding. Those chunks would be dropped before
/// decode-through ever ran. This gate lets the scan entry route such a chunk
/// into a decode-only pass instead of skipping it, bounded to chunks that
/// actually look encoded so normal traffic keeps the fast skip.
#[cfg(feature = "decode")]
pub(crate) fn has_decodable_payload(data: &[u8]) -> bool {
    // Static XOR programs can consist entirely of short decimal literals, so
    // they do not necessarily contain the long base64/hex run recognized by
    // the byte-density loop below. Without this marker pair the SIMD entry
    // path can skip decode post-processing while CPU fallback runs it, causing
    // backend-dependent recall. The full bounded grammar still validates the
    // source in `javascript_static`; this is admission only.
    let mut run = 0usize;
    let mut percent_escapes = 0usize;
    let mut backslash_escapes = 0usize;
    let mut html_numeric_entities = 0usize;
    let mut has_from_char_code = false;
    let mut has_xor_operator = false;
    let mut i = 0usize;

    while i < data.len() {
        let b = data[i];

        if b == b'^' {
            has_xor_operator = true;
            if has_from_char_code {
                return true;
            }
        } else if b == b'f' && data[i..].starts_with(b"fromCharCode") {
            has_from_char_code = true;
            if has_xor_operator {
                return true;
            }
        }

        if b == b'%'
            && i + 2 < data.len()
            && data[i + 1].is_ascii_hexdigit()
            && data[i + 2].is_ascii_hexdigit()
        {
            percent_escapes += 1;
            if percent_escapes >= limits::MIN_PERCENT_ESCAPES {
                return true;
            }
            run = 0;
            i += 3;
            continue;
        }

        if b == b'&' {
            if let Some(entity_len) = valid_html_numeric_entity_len(&data[i..]) {
                html_numeric_entities += 1;
                if html_numeric_entities >= limits::MIN_HTML_NUMERIC_ENTITIES {
                    return true;
                }
                run = 0;
                i += entity_len;
                continue;
            }
        }

        if b == b'\\' && i + 1 < data.len() {
            match data[i + 1] {
                b'u' if i + 5 < data.len()
                    && data[i + 2..i + 6]
                        .iter()
                        .all(|digit| digit.is_ascii_hexdigit()) =>
                {
                    backslash_escapes += 1;
                    if backslash_escapes >= limits::MIN_BACKSLASH_ESCAPES {
                        return true;
                    }
                    run = 0;
                    i += 6;
                    continue;
                }
                b'x' if i + 3 < data.len()
                    && data[i + 2..i + 4]
                        .iter()
                        .all(|digit| digit.is_ascii_hexdigit()) =>
                {
                    backslash_escapes += 1;
                    if backslash_escapes >= limits::MIN_BACKSLASH_ESCAPES {
                        return true;
                    }
                    run = 0;
                    i += 4;
                    continue;
                }
                // C-style octal escape `\NNN` (exactly 3 octal digits), the
                // trigger grammar of `OctalEscapeDecoder::contains_octal_escape`.
                // Without this arm the octal digits between the backslashes form
                // runs of only 3 (well under MIN_DECODABLE_RUN=24) and no other
                // arm matches, so an octal-ONLY chunk returned false here and the
                // whole decode pipeline was skipped, leaving the registered
                // octal decoder unreachable for octal-encoded payloads (a silent
                // recall hole, Law 10). Counts toward the same backslash-escape
                // threshold as `\u`/`\x` so octal reaches detection parity with
                // its sibling escapes.
                b'0'..=b'7'
                    if i + 3 < data.len()
                        && (b'0'..=b'7').contains(&data[i + 2])
                        && (b'0'..=b'7').contains(&data[i + 3]) =>
                {
                    backslash_escapes += 1;
                    if backslash_escapes >= limits::MIN_BACKSLASH_ESCAPES {
                        return true;
                    }
                    run = 0;
                    i += 4;
                    continue;
                }
                _ => {}
            }
        }

        // base64 (standard + url-safe) and hex share this alphabet; padding
        // `=` is included so a trailing-padded blob still counts.
        if is_base64_candidate_byte(b) {
            run += 1;
            if run >= limits::MIN_DECODABLE_RUN {
                return true;
            }
        } else {
            run = 0;
        }
        i += 1;
    }
    false
}

/// A trait for decoding chunks to find hidden secrets.
pub trait Decoder: Send + Sync {
    fn name(&self) -> &'static str;

    /// Bounded work projection for this decoder on `chunk`.
    ///
    /// Custom decoders default to an unknown, conservative sketch. Built-in
    /// decoders override this beside the grammar used by `decode_chunk`.
    fn admission_sketch(&self, _chunk: &Chunk) -> DecodeAdmissionSketch {
        DecodeAdmissionSketch::UNKNOWN
    }

    /// Whether this decoder can produce output for `chunk`.
    ///
    /// Custom decoders default to [`DecodeAdmission::Unknown`], which always
    /// fails open. Built-in decoders derive this from the sketch owned next to
    /// the grammar used by [`Self::decode_chunk`]. Only `Impossible` permits the
    /// engine to skip decode post-processing.
    fn admission(&self, _chunk: &Chunk) -> DecodeAdmission {
        self.admission_sketch(_chunk).admission()
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk>;
}

/// Bounded, content-free projection of decoder work.
///
/// The sketch contains only decoder-mechanism bits and saturating cost counters.
/// It carries no source bytes, offsets, values, or content-derived hashes, so
/// it is safe to persist as part of autoroute workload identity.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct DecodeAdmissionSketch {
    kind_mask: u32,
    candidate_count: u16,
    candidate_bytes: u32,
    unknown: bool,
}

impl DecodeAdmissionSketch {
    pub const BASE64: u32 = 1 << 0;
    pub const HEX: u32 = 1 << 1;
    pub const URL: u32 = 1 << 2;
    pub const QUOTED_PRINTABLE: u32 = 1 << 3;
    pub const HTML_NAMED_ENTITY: u32 = 1 << 4;
    pub const HTML_NUMERIC_ENTITY: u32 = 1 << 5;
    pub const OCTAL_ESCAPE: u32 = 1 << 6;
    pub const MIME_ENCODED_WORD: u32 = 1 << 7;
    pub const JSON: u32 = 1 << 8;
    pub const UNICODE_ESCAPE: u32 = 1 << 9;
    pub const Z85: u32 = 1 << 10;
    pub const JAVASCRIPT_STATIC: u32 = 1 << 11;
    pub const REVERSE: u32 = 1 << 12;
    pub const CAESAR: u32 = 1 << 13;
    /// Bounded gzip/zlib inflation reached through the base64 decoder.
    pub const COMPRESSED_CONTAINER: u32 = 1 << 14;

    pub const NONE: Self = Self {
        kind_mask: 0,
        candidate_count: 0,
        candidate_bytes: 0,
        unknown: false,
    };

    pub const UNKNOWN: Self = Self {
        kind_mask: 0,
        candidate_count: u16::MAX,
        candidate_bytes: u32::MAX,
        unknown: true,
    };

    pub const fn kind_mask(self) -> u32 {
        self.kind_mask
    }

    pub const fn candidate_count(self) -> u16 {
        self.candidate_count
    }

    pub const fn candidate_bytes(self) -> u32 {
        self.candidate_bytes
    }

    pub const fn has_unknown(self) -> bool {
        self.unknown
    }

    pub fn merge(&mut self, other: Self) {
        self.kind_mask |= other.kind_mask;
        self.candidate_count = self.candidate_count.saturating_add(other.candidate_count);
        self.candidate_bytes = self.candidate_bytes.saturating_add(other.candidate_bytes);
        self.unknown |= other.unknown;
        if self.unknown {
            self.candidate_count = u16::MAX;
            self.candidate_bytes = u32::MAX;
        }
    }

    pub(crate) fn possible(kind: u32, candidate_count: usize, candidate_bytes: usize) -> Self {
        Self {
            kind_mask: kind,
            candidate_count: candidate_count.min(u16::MAX as usize) as u16,
            candidate_bytes: candidate_bytes.min(u32::MAX as usize) as u32,
            unknown: false,
        }
    }

    pub(crate) const fn admission(self) -> DecodeAdmission {
        if self.unknown {
            DecodeAdmission::Unknown
        } else if self.kind_mask == 0 {
            DecodeAdmission::Impossible
        } else {
            DecodeAdmission::Possible
        }
    }
}

/// Effective immutable decode policy captured from one compiled scanner.
///
/// Autoroute keeps this value with its router so workload classification uses
/// the same decode enablement and input ceiling as the scanner it will run.
#[derive(Clone, Debug)]
pub struct DecodeWorkloadPlan {
    enabled: bool,
    max_input_bytes: usize,
    transforms: DecodeTransformPolicyHandle,
}

#[derive(Clone, Debug)]
enum DecodeTransformPolicyHandle {
    Bundled,
    Compiled(std::sync::Arc<policy::CompiledDecodeTransformPolicy>),
}

impl DecodeTransformPolicyHandle {
    fn policy(&self) -> &policy::CompiledDecodeTransformPolicy {
        match self {
            Self::Bundled => policy::bundled_compat_policy(),
            Self::Compiled(policy) => policy,
        }
    }
}

impl PartialEq for DecodeWorkloadPlan {
    fn eq(&self, other: &Self) -> bool {
        self.enabled == other.enabled
            && self.max_input_bytes == other.max_input_bytes
            && self.transforms.policy().identity() == other.transforms.policy().identity()
    }
}

impl Eq for DecodeWorkloadPlan {}

impl DecodeWorkloadPlan {
    /// Resolve decode enablement from the same depth and byte limits consumed
    /// by [`crate::ScannerConfig`]. A zero depth disables the mechanism. This
    /// standalone constructor uses the bundled compatibility prefix policy;
    /// [`crate::CompiledScanner::decode_workload_plan`] carries its exact active
    /// detector policy instead.
    pub const fn from_limits(max_depth: usize, max_input_bytes: usize) -> Self {
        Self {
            enabled: cfg!(feature = "decode") && max_depth > 0,
            max_input_bytes,
            transforms: DecodeTransformPolicyHandle::Bundled,
        }
    }

    pub(crate) fn from_compiled_limits(
        max_depth: usize,
        max_input_bytes: usize,
        transforms: std::sync::Arc<policy::CompiledDecodeTransformPolicy>,
    ) -> Self {
        Self {
            enabled: cfg!(feature = "decode") && max_depth > 0,
            max_input_bytes,
            transforms: DecodeTransformPolicyHandle::Compiled(transforms),
        }
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    pub const fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }

    pub fn admits(&self, chunk: &Chunk) -> bool {
        self.enabled && chunk.data.len() <= self.max_input_bytes
    }

    /// Project work only when the compiled scanner can execute decode-through
    /// for this exact chunk.
    pub fn sketch(&self, chunk: &Chunk) -> DecodeAdmissionSketch {
        #[cfg(not(feature = "decode"))]
        {
            let _ = chunk;
            return DecodeAdmissionSketch::NONE;
        }
        #[cfg(feature = "decode")]
        if !self.admits(chunk) {
            DecodeAdmissionSketch::NONE
        } else {
            pipeline::decoder_admission_sketch(chunk, self.transforms.policy())
        }
    }
}

/// Compute a standalone decode work sketch with the bundled compatibility
/// prefix policy. Autoroute uses [`crate::CompiledScanner::decode_workload_plan`]
/// so its sketch matches the active detector corpus.
#[cfg(feature = "decode")]
pub fn decode_admission_sketch(chunk: &Chunk) -> DecodeAdmissionSketch {
    pipeline::decoder_admission_sketch(chunk, policy::bundled_compat_policy())
}

/// Decode-disabled builds contribute no decoder work to autoroute identity.
#[cfg(not(feature = "decode"))]
pub fn decode_admission_sketch(_chunk: &Chunk) -> DecodeAdmissionSketch {
    DecodeAdmissionSketch::NONE
}

/// Proof carried from decoder-owned grammars to the scan admission path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DecodeAdmission {
    /// The decoder does not expose a complete admission predicate. Fail open.
    Unknown,
    /// The decoder grammar can produce at least one output candidate.
    Possible,
    /// The decoder grammar proves that it cannot produce output.
    Impossible,
}

/// Candidate encoded string discovered during pre-decoding extraction.
pub struct EncodedString {
    pub value: String,
}
