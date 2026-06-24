//! Decode-through scanning: decode encoded strings before pattern matching.
//!
//! Catches secrets hidden behind encoding layers - Kubernetes manifests,
//! CI/CD configs, URL-escaped payloads, string escapes, and hex-encoded
//! credentials.

mod base64;
pub(crate) mod caesar;
pub(crate) mod hex;
mod json;
mod pipeline;
pub(crate) mod reverse;
mod unicode_escape;
mod url;
pub(crate) mod util;

pub use base64::{base64_decode, find_base64_strings, z85_decode};
pub(crate) use base64::{is_base64_candidate_byte, is_standard_base64_byte, standard_base64_shape};
pub use hex::{find_hex_strings, hex_decode};
pub(crate) use pipeline::decode_chunk;
pub use pipeline::register_decoder;
#[cfg(test)]
pub(crate) use pipeline::{ScopedDecoderRegistration, register_thread_decoder};
pub(crate) use pipeline::{
    decoder_profile_dump, decoder_profile_reset, extract_profile_dump, extract_profile_reset,
};
pub(crate) use util::take_hex_digits;

use keyhog_core::Chunk;

pub(crate) fn unicode_escape_decode(input: &str) -> Result<String, ()> {
    unicode_escape::unicode_escape_decode(input)
}

pub(crate) fn extracted_value_strings_for_test(text: &str) -> Vec<String> {
    pipeline::with_extracted_value_spans(text, |values| {
        values.iter().map(|value| value.value.clone()).collect()
    })
}

/// Minimum contiguous encoded-alphabet run that makes a chunk worth decoding.
/// A base64 of a ~16-byte secret is ~24 chars; shorter runs are too small to
/// hide a credential and would only add prefilter-bypass cost.
#[cfg(feature = "decode")]
const MIN_DECODABLE_RUN: usize = 24;
#[cfg(feature = "decode")]
const MIN_PERCENT_ESCAPES: usize = 4;
#[cfg(feature = "decode")]
const MIN_BACKSLASH_ESCAPES: usize = 2;

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
    let mut run = 0usize;
    let mut percent_escapes = 0usize;
    let mut backslash_escapes = 0usize;
    let mut i = 0usize;

    while i < data.len() {
        let b = data[i];

        if b == b'%'
            && i + 2 < data.len()
            && data[i + 1].is_ascii_hexdigit()
            && data[i + 2].is_ascii_hexdigit()
        {
            percent_escapes += 1;
            if percent_escapes >= MIN_PERCENT_ESCAPES {
                return true;
            }
            run = 0;
            i += 3;
            continue;
        }

        if b == b'\\' && i + 1 < data.len() {
            match data[i + 1] {
                b'u' if i + 5 < data.len()
                    && data[i + 2..i + 6]
                        .iter()
                        .all(|digit| digit.is_ascii_hexdigit()) =>
                {
                    backslash_escapes += 1;
                    if backslash_escapes >= MIN_BACKSLASH_ESCAPES {
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
                    if backslash_escapes >= MIN_BACKSLASH_ESCAPES {
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
            if run >= MIN_DECODABLE_RUN {
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
    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk>;
}

/// Candidate encoded string discovered during pre-decoding extraction.
pub struct EncodedString {
    pub value: String,
}
