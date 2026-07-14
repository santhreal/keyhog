//! Autoroute workload bucketing and source-shape fingerprints.

use keyhog_core::Chunk;
use keyhog_scanner::decode::is_base64_candidate_byte;
use serde::{Deserialize, Serialize};
use std::fmt;

const AUTOROUTE_DECODE_DENSITY_SAMPLE_BYTES: usize = 64 * 1024;
const AUTOROUTE_DECODE_MIN_ENCODED_RUN: usize = 24;
const AUTOROUTE_DECODE_SAMPLE_STRATA: usize = 16;
const AUTOROUTE_DECODE_MIN_STRATA: usize = 3;
const AUTOROUTE_DECODE_MIN_CHUNK_SAMPLE: usize =
    AUTOROUTE_DECODE_MIN_ENCODED_RUN * AUTOROUTE_DECODE_MIN_STRATA;

// `Ord` gives the multi-config cache a deterministic on-disk decision order
// (decisions are collected through a `BTreeMap<WorkloadKey, _>` on save), so a
// recalibration that re-measures the same buckets produces a byte-stable file.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkloadKey {
    pub(super) bytes_bucket: u8,
    pub(super) chunks_bucket: u8,
    pub(super) max_file_bucket: u8,
    pub(super) pattern_bucket: u8,
    pub(super) decode_density_bucket: u8,
    pub(super) source_class_hash: u64,
}

/// Render a bucket identically in fail-closed routing errors and cache
/// inspection, so operators can match a refused workload field-for-field.
pub(super) fn render_workload_key(key: &WorkloadKey) -> String {
    format!(
        "bytes_log2={} chunks_log2={} max_file_log2={} patterns_log2={} \
         decode_density_log2={} source_hash={:016x}",
        key.bytes_bucket,
        key.chunks_bucket,
        key.max_file_bucket,
        key.pattern_bucket,
        key.decode_density_bucket,
        key.source_class_hash
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WorkloadClassificationError {
    MissingSourceFamily {
        source_type: String,
        path: Option<String>,
    },
    DecodeSampleBudgetExceeded {
        minimum_sample_bytes: usize,
        chunk_count: usize,
    },
}

impl WorkloadClassificationError {
    fn missing_source_family(chunk: &Chunk) -> Self {
        Self::MissingSourceFamily {
            source_type: chunk.metadata.source_type.to_string(),
            path: chunk.metadata.path.as_deref().map(|s| s.to_string()),
        }
    }
}

impl fmt::Display for WorkloadClassificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSourceFamily {
                source_type,
                path: Some(path),
            } => write!(
                f,
                "chunk at {path} has invalid source_type {source_type:?}; every autorouted chunk must carry a non-empty source family"
            ),
            Self::MissingSourceFamily {
                source_type,
                path: None,
            } => write!(
                f,
                "chunk has invalid source_type {source_type:?}; every autorouted chunk must carry a non-empty source family"
            ),
            Self::DecodeSampleBudgetExceeded {
                minimum_sample_bytes,
                chunk_count,
            } => write!(
                f,
                "autoroute cannot classify decode density for {chunk_count} chunks within its {}-byte sampling cap: representative coverage requires at least {minimum_sample_bytes} bytes; lower --fused-batch or [scan].fused_batch and recalibrate",
                AUTOROUTE_DECODE_DENSITY_SAMPLE_BYTES
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
        decode_density_bucket: autoroute_stable_density_bucket(decode_density_bucket(batch)?),
        source_class_hash: source_class_hash(batch)?,
    })
}

pub(super) fn autoroute_stable_bucket(value: u64) -> u8 {
    log2_bucket(value)
}

pub(super) fn autoroute_stable_density_bucket(raw_bucket: u8) -> u8 {
    raw_bucket.saturating_add(1) / 2
}

#[derive(Clone, Copy)]
struct DecodeSamplePlan {
    residual_bytes: u128,
    extra_bytes: u128,
}

impl DecodeSamplePlan {
    fn quota(self, chunk_len: usize) -> usize {
        let base = chunk_len.min(AUTOROUTE_DECODE_MIN_CHUNK_SAMPLE);
        let residual = chunk_len - base;
        if residual == 0 || self.residual_bytes == 0 {
            return base;
        }
        let extra = self.extra_bytes * residual as u128 / self.residual_bytes;
        base + extra as usize
    }
}

// Every non-short chunk gets enough evidence for three encoded runs. The
// remaining fixed budget is divided by bytes, without order or ties.
fn decode_sample_plan(batch: &[Chunk]) -> Result<DecodeSamplePlan, WorkloadClassificationError> {
    let mut base_bytes = 0usize;
    let mut residual_bytes = 0u128;
    let mut chunk_count = 0usize;

    for chunk in batch {
        let len = chunk.data.len();
        if len == 0 {
            continue;
        }
        chunk_count += 1;
        base_bytes = base_bytes.saturating_add(len.min(AUTOROUTE_DECODE_MIN_CHUNK_SAMPLE));
        residual_bytes += (len - len.min(AUTOROUTE_DECODE_MIN_CHUNK_SAMPLE)) as u128;
    }
    if base_bytes > AUTOROUTE_DECODE_DENSITY_SAMPLE_BYTES {
        return Err(WorkloadClassificationError::DecodeSampleBudgetExceeded {
            minimum_sample_bytes: base_bytes,
            chunk_count,
        });
    }
    let remaining = AUTOROUTE_DECODE_DENSITY_SAMPLE_BYTES - base_bytes;
    Ok(DecodeSamplePlan {
        residual_bytes,
        extra_bytes: (remaining as u128).min(residual_bytes),
    })
}

pub(super) fn decode_density_bucket(batch: &[Chunk]) -> Result<u8, WorkloadClassificationError> {
    let plan = decode_sample_plan(batch)?;
    let mut sampled = 0usize;
    let mut encoded_candidate_bytes = 0usize;
    let mut decode_trigger_bytes = 0usize;

    for chunk in batch {
        let bytes = chunk.data.as_bytes();
        let quota = plan.quota(bytes.len());
        for_each_decode_sample_window(bytes, quota, |window| {
            sampled = sampled.saturating_add(window.len());
            accumulate_decode_density_window(
                window,
                &mut encoded_candidate_bytes,
                &mut decode_trigger_bytes,
            );
        });
    }
    debug_assert!(sampled <= AUTOROUTE_DECODE_DENSITY_SAMPLE_BYTES);
    if sampled == 0 {
        return Ok(0);
    }

    let weighted_decode_bytes =
        encoded_candidate_bytes.saturating_add(decode_trigger_bytes.min(sampled / 4));
    let score_per_kib = (weighted_decode_bytes as u64).saturating_mul(1024) / sampled as u64;
    Ok(log2_bucket(score_per_kib))
}

fn for_each_decode_sample_window(bytes: &[u8], quota: usize, mut visit: impl FnMut(&[u8])) {
    if quota == 0 {
        return;
    }
    if quota >= bytes.len() {
        visit(bytes);
        return;
    }

    let strata = AUTOROUTE_DECODE_SAMPLE_STRATA.min(quota / AUTOROUTE_DECODE_MIN_ENCODED_RUN);
    debug_assert!(strata >= AUTOROUTE_DECODE_MIN_STRATA);
    let gaps = bytes.len() - quota;
    for index in 0..strata {
        let sampled_before = index * quota / strata;
        let sampled_after = (index + 1) * quota / strata;
        let gap_parts = strata - 1;
        let gap_before = (gaps / gap_parts) * index + (gaps % gap_parts) * index / gap_parts;
        let start = sampled_before + gap_before;
        let end = sampled_after + gap_before;
        visit(&bytes[start..end]);
    }
}

fn accumulate_decode_density_window(
    window: &[u8],
    encoded_candidate_bytes: &mut usize,
    decode_trigger_bytes: &mut usize,
) {
    let mut encoded_run = 0usize;
    for &byte in window {
        if is_base64_candidate_byte(byte) {
            encoded_run += 1;
        } else {
            if encoded_run >= AUTOROUTE_DECODE_MIN_ENCODED_RUN {
                *encoded_candidate_bytes = encoded_candidate_bytes.saturating_add(encoded_run);
            }
            encoded_run = 0;
        }
        if is_decode_trigger_byte(byte) {
            *decode_trigger_bytes = decode_trigger_bytes.saturating_add(1);
        }
    }
    if encoded_run >= AUTOROUTE_DECODE_MIN_ENCODED_RUN {
        *encoded_candidate_bytes = encoded_candidate_bytes.saturating_add(encoded_run);
    }
}

#[cfg(test)]
pub(super) fn planned_decode_sample_bytes(
    batch: &[Chunk],
) -> Result<usize, WorkloadClassificationError> {
    let plan = decode_sample_plan(batch)?;
    Ok(batch.iter().map(|chunk| plan.quota(chunk.data.len())).sum())
}

#[cfg(test)]
pub(super) fn planned_decode_sample_quotas(
    batch: &[Chunk],
) -> Result<Vec<usize>, WorkloadClassificationError> {
    let plan = decode_sample_plan(batch)?;
    Ok(batch
        .iter()
        .map(|chunk| plan.quota(chunk.data.len()))
        .collect())
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
