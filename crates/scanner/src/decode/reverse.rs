use super::pipeline::{decode_candidate_refs_exact, with_extracted_value_spans};
use super::{DecodeAdmissionSketch, Decoder};
use keyhog_core::Chunk;

/// Match secrets that have been reversed character-by-character to dodge a
/// naïve byte-substring scan. Cheap evasion the adversarial corpus
/// (release-2026-04-26) hits multiple times - `RNK1ESEMURKWESFEDBA-46AIKA`
/// is exactly the AWS access-key-id `AKIA-64ABDEFSEWKRUMSEK1NR` reversed.
///
/// The reverse decoder runs *after* the other decoders fail to match. It only
/// emits a decoded chunk when the candidate is at least 16 chars long; below
/// that, reversed strings collide with normal text and produce too many
/// useless chunks for the scanner to dedup.
pub(crate) struct ReverseDecoder;

/// Semantic alias of the shared evasion-decode floor, same value as
/// `caesar::MIN_CAESAR_LEN`, owned once in [`super::util::MIN_EVASION_DECODE_LEN`].
const MIN_REVERSE_LEN: usize = super::util::MIN_EVASION_DECODE_LEN;

/// Minimum contiguous ASCII-alphanumeric run (scanned in the reversed
/// direction) for a candidate to be worth reverse-decoding. Filters
/// `a-b-c-d-…` and other punctuated prose whose longest run is short. The
/// sibling Caesar decoder names the same kind of gate `MIN_ALNUM_RUN`.
const MIN_REVERSE_ALNUM_RUN: usize = 12;

impl ReverseDecoder {
    pub(super) fn admission_sketch_with_policy(
        &self,
        chunk: &Chunk,
        policy: &super::policy::CompiledDecodeTransformPolicy,
    ) -> DecodeAdmissionSketch {
        if chunk.metadata.source_type.contains("/reverse") {
            return DecodeAdmissionSketch::NONE;
        }
        with_extracted_value_spans(&chunk.data, |candidates| {
            let mut count = 0usize;
            let mut bytes = 0usize;
            for candidate in candidates
                .iter()
                .filter(|candidate| is_reverse_candidate(candidate, policy))
            {
                count = count.saturating_add(1);
                bytes = bytes.saturating_add(candidate.value.len());
            }
            if count == 0 {
                DecodeAdmissionSketch::NONE
            } else {
                DecodeAdmissionSketch::possible(DecodeAdmissionSketch::REVERSE, count, bytes)
            }
        })
    }

    pub(super) fn decode_chunk_with_policy(
        &self,
        chunk: &Chunk,
        policy: &super::policy::CompiledDecodeTransformPolicy,
    ) -> Vec<Chunk> {
        if chunk.metadata.source_type.contains("/reverse") {
            return Vec::new();
        }
        with_extracted_value_spans(&chunk.data, |candidates| {
            decode_candidate_refs_exact(
                chunk,
                candidates
                    .iter()
                    .filter(|candidate| is_reverse_candidate(candidate, policy)),
                |s| Ok(reverse_str(s)),
                self.name(),
            )
        })
    }
}

impl Decoder for ReverseDecoder {
    fn name(&self) -> &'static str {
        "reverse"
    }

    fn admission_sketch(&self, chunk: &Chunk) -> DecodeAdmissionSketch {
        self.admission_sketch_with_policy(chunk, super::policy::bundled_compat_policy())
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        self.decode_chunk_with_policy(chunk, super::policy::bundled_compat_policy())
    }
}

fn is_reverse_candidate(
    candidate: &super::pipeline::ExtractedValue,
    policy: &super::policy::CompiledDecodeTransformPolicy,
) -> bool {
    candidate.value.len() >= MIN_REVERSE_LEN
        && !crate::suppression::shape::looks_like_prefixed_hash_digest(&candidate.value)
        && looks_reversible_with_policy(&candidate.value, policy)
}

pub(crate) fn reverse_str(s: &str) -> String {
    s.chars().rev().collect()
}

/// Reverse-decode is asymmetric: every string trivially "decodes" to its
/// reverse, so we'd emit O(N) decoy chunks for normal text. Two cheap gates:
///
/// 1. A 12+ ASCII alphanumeric run in the reversed direction (filters out
///    `a-b-c-d-...` and other punctuated text).
/// 2. The reversed text must contain at least one prefix declared for reverse
///    recovery by the active detector corpus. Without this, plain prose like
///    `ABCDEFGHIJKLMNOPQRSTUVWXYZ` reverses to `ZYXWVUTSRQPONMLKJIHGFEDCBA`,
///    passes the alphanumeric-run gate, and gets emitted as a decoy chunk
///    on every chunk that contains a long alphanumeric word - pure noise
///    that hammers the dedup layer. Kimi-decode audit finding #4.
pub(crate) fn looks_reversible(candidate: &str) -> bool {
    looks_reversible_with_policy(candidate, super::policy::bundled_compat_policy())
}

fn looks_reversible_with_policy(
    candidate: &str,
    policy: &super::policy::CompiledDecodeTransformPolicy,
) -> bool {
    let bytes = candidate.as_bytes();
    let mut run = 0usize;
    let mut saw_long_run = false;
    for &b in bytes.iter().rev() {
        if b.is_ascii_alphanumeric() {
            run += 1;
            if run >= MIN_REVERSE_ALNUM_RUN {
                saw_long_run = true;
                break;
            }
        } else {
            run = 0;
        }
    }
    if !saw_long_run {
        return false;
    }
    // Only emit a reverse-decoded chunk when the reversed string would
    // contain an active detector prefix. Stops `ZYXWVUTSRQPONMLKJIHGFEDCBA`
    // from looking like a candidate just because it has a long alnum run.
    //
    // Detector schema validation rejects prefixes shorter than three bytes.
    // Two-byte strings such as `0x` occur often enough by chance in encoded
    // data to create excessive reverse fan-out.
    policy.reverse_matches(candidate)
}
