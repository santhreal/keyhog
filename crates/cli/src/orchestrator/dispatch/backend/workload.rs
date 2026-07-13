//! Autoroute workload bucketing and source-shape fingerprints.

use keyhog_core::Chunk;
use keyhog_scanner::decode::is_base64_candidate_byte;
use serde::{Deserialize, Serialize};
use std::fmt;

const AUTOROUTE_DECODE_DENSITY_SAMPLE_BYTES: usize = 64 * 1024;
const AUTOROUTE_DECODE_MIN_ENCODED_RUN: usize = 24;

// `Ord` gives the multi-config cache a deterministic on-disk decision order
// (decisions are collected through a `BTreeMap<WorkloadKey, _>` on save), so a
// recalibration that re-measures the same buckets produces a byte-stable file.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(super) struct WorkloadKey {
    pub(super) bytes_bucket: u8,
    pub(super) chunks_bucket: u8,
    pub(super) max_file_bucket: u8,
    pub(super) pattern_bucket: u8,
    pub(super) decode_density_bucket: u8,
    pub(super) source_class_hash: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WorkloadClassificationError {
    source_type: String,
    path: Option<String>,
}

impl WorkloadClassificationError {
    fn missing_source_family(chunk: &Chunk) -> Self {
        Self {
            source_type: chunk.metadata.source_type.to_string(),
            path: chunk.metadata.path.as_deref().map(|s| s.to_string()),
        }
    }
}

impl fmt::Display for WorkloadClassificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.path.as_deref() {
            Some(path) => write!(
                f,
                "chunk at {path} has invalid source_type {:?}; every autorouted chunk must carry a non-empty source family",
                self.source_type
            ),
            None => write!(
                f,
                "chunk has invalid source_type {:?}; every autorouted chunk must carry a non-empty source family",
                self.source_type
            ),
        }
    }
}

impl std::error::Error for WorkloadClassificationError {}

pub(super) fn workload_key(
    batch: &[Chunk],
    pattern_count: usize,
) -> Result<WorkloadKey, WorkloadClassificationError> {
    let bytes: u64 = batch.iter().map(|c| c.data.len() as u64).sum();
    let max_file = batch
        .iter()
        .map(|c| c.metadata.size_bytes.unwrap_or(c.data.len() as u64)) // LAW10: empty/absent => documented numeric default, recall-safe
        .max()
        .unwrap_or(0); // LAW10: empty/absent => documented numeric default, recall-safe
    Ok(WorkloadKey {
        bytes_bucket: autoroute_stable_bucket(bytes),
        chunks_bucket: autoroute_stable_bucket(batch.len() as u64),
        max_file_bucket: autoroute_stable_bucket(max_file),
        pattern_bucket: log2_bucket(pattern_count as u64),
        decode_density_bucket: autoroute_stable_density_bucket(decode_density_bucket(batch)),
        source_class_hash: source_class_hash(batch)?,
    })
}

pub(super) fn autoroute_stable_bucket(value: u64) -> u8 {
    log2_bucket(value)
}

pub(super) fn autoroute_stable_density_bucket(raw_bucket: u8) -> u8 {
    raw_bucket.saturating_add(1) / 2
}

pub(super) fn decode_density_bucket(batch: &[Chunk]) -> u8 {
    let mut sampled = 0usize;
    let mut encoded_run = 0usize;
    let mut encoded_candidate_bytes = 0usize;
    let mut decode_trigger_bytes = 0usize;

    for chunk in batch {
        if sampled >= AUTOROUTE_DECODE_DENSITY_SAMPLE_BYTES {
            break;
        }
        for &byte in chunk.data.as_bytes() {
            if sampled >= AUTOROUTE_DECODE_DENSITY_SAMPLE_BYTES {
                break;
            }
            sampled += 1;
            if is_base64_candidate_byte(byte) {
                encoded_run += 1;
            } else {
                if encoded_run >= AUTOROUTE_DECODE_MIN_ENCODED_RUN {
                    encoded_candidate_bytes = encoded_candidate_bytes.saturating_add(encoded_run);
                }
                encoded_run = 0;
            }
            if is_decode_trigger_byte(byte) {
                decode_trigger_bytes = decode_trigger_bytes.saturating_add(1);
            }
        }
        if encoded_run >= AUTOROUTE_DECODE_MIN_ENCODED_RUN {
            encoded_candidate_bytes = encoded_candidate_bytes.saturating_add(encoded_run);
        }
        encoded_run = 0;
    }
    if sampled == 0 {
        return 0;
    }

    let weighted_decode_bytes =
        encoded_candidate_bytes.saturating_add(decode_trigger_bytes.min(sampled / 4));
    let score_per_kib = (weighted_decode_bytes as u64).saturating_mul(1024) / sampled as u64;
    log2_bucket(score_per_kib)
}

fn is_decode_trigger_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'%' | b'&' | b'\\' | b'"' | b'\'' | b'{' | b'}' | b'='
    )
}

pub(super) fn source_class_hash(batch: &[Chunk]) -> Result<u64, WorkloadClassificationError> {
    // `size_bytes` is the original backing-source size; its absence means the
    // max-size bucket was derived from a stream or transformed payload. Bind
    // that provenance to each source family so numerically equal buckets do
    // not reuse measurements made for a different kind of workload evidence.
    let mut classes: Vec<(&str, bool)> = Vec::new();
    for chunk in batch {
        classes.push((source_family(chunk)?, chunk.metadata.size_bytes.is_some()));
    }
    classes.sort_unstable();
    classes.dedup();
    let mut h = crate::stable_hash::StableHasher::new("autoroute-source-class");
    h.field_usize("classes.len", classes.len());
    for (class, has_full_size) in classes {
        h.field_str("class", class);
        h.field_bool("class.has_full_size", has_full_size);
    }
    Ok(h.finish_u64())
}

fn source_family(chunk: &Chunk) -> Result<&str, WorkloadClassificationError> {
    chunk
        .metadata
        .source_type
        .trim()
        .split([':', '/'])
        .next()
        .filter(|family| !family.is_empty())
        .ok_or_else(|| WorkloadClassificationError::missing_source_family(chunk))
}

pub(super) fn log2_bucket(value: u64) -> u8 {
    if value == 0 {
        0
    } else {
        (u64::BITS - value.leading_zeros()) as u8
    }
}
