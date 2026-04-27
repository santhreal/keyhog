//! Decode-through scanning: decode base64 and hex strings before pattern matching.
//!
//! Catches secrets hidden behind encoding layers — Kubernetes manifests,
//! CI/CD configs, and hex-encoded credentials.

mod base64;
mod caesar;
mod hex;
mod pipeline;
mod reverse;
mod url;

pub use base64::{base64_decode, find_base64_strings, z85_decode};
pub use hex::hex_decode;
pub use pipeline::{decode_chunk, register_decoder};

use keyhog_core::Chunk;

/// A trait for decoding chunks to find hidden secrets.
pub trait Decoder: Send + Sync {
    fn name(&self) -> &'static str;
    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk>;
}

/// Candidate encoded string discovered during pre-decoding extraction.
pub struct EncodedString {
    pub value: String,
}
