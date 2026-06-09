//! Decode-through scanning: decode base64 and hex strings before pattern matching.
//!
//! Catches secrets hidden behind encoding layers - Kubernetes manifests,
//! CI/CD configs, and hex-encoded credentials.

mod base64;
pub mod caesar;
pub mod hex;
mod json;
mod pipeline;
pub mod reverse;
mod unicode_escape;
mod url;
pub mod util;

pub use base64::{base64_decode, find_base64_strings, z85_decode};
pub use hex::hex_decode;
pub use pipeline::{decode_chunk, decoder_profile_dump, extract_profile_dump, register_decoder};

use keyhog_core::Chunk;

/// Minimum contiguous encoded-alphabet run that makes a chunk worth decoding.
/// A base64 of a ~16-byte secret is ~24 chars; shorter runs are too small to
/// hide a credential and would only add prefilter-bypass cost.
const MIN_DECODABLE_RUN: usize = 24;

/// Cheap O(n), allocation-free gate: does `data` contain a contiguous run of
/// base64-/hex-alphabet bytes long enough to plausibly hide an encoded secret?
///
/// The direct-match prefilters (`AlphabetScreen`, the bigram bloom) reject a
/// chunk that carries none of any detector's literal bytes/bigrams - which is
/// EXACTLY the shape of a fully-encoded secret (`data = "<base64>"`), whose
/// plaintext keyword/prefix only appears AFTER decoding. Those chunks would be
/// dropped before decode-through ever ran. This gate lets the scan entry route
/// such a chunk into a decode-only pass instead of skipping it, bounded to
/// chunks that actually look encoded so normal traffic keeps the fast skip.
pub(crate) fn has_decodable_payload(data: &[u8]) -> bool {
    let mut run = 0usize;
    for &b in data {
        // base64 (standard + url-safe) and hex share this alphabet; padding
        // `=` is included so a trailing-padded blob still counts.
        let encoded_byte =
            b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_');
        if encoded_byte {
            run += 1;
            if run >= MIN_DECODABLE_RUN {
                return true;
            }
        } else {
            run = 0;
        }
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
