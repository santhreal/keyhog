//! Autoroute workload bucketing and source-shape fingerprints.

use keyhog_core::Chunk;
use keyhog_scanner::decode::{DecodeAdmissionSketch, DecodeWorkloadPlan};
use keyhog_scanner::Phase1AdmissionSummary;
use serde::{Deserialize, Serialize};
use std::fmt;

const AUTOROUTE_DECODE_SAMPLE_BYTES: usize = 64 * 1024;
const AUTOROUTE_DECODE_SAMPLE_WINDOW_BYTES: usize = 64;
const AUTOROUTE_DECODE_SAMPLE_STRATA: usize = 16;
const AUTOROUTE_DECODE_MIN_STRATA: usize = 3;
const AUTOROUTE_DECODE_MIN_CHUNK_SAMPLE: usize =
    AUTOROUTE_DECODE_SAMPLE_WINDOW_BYTES * AUTOROUTE_DECODE_MIN_STRATA;

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
    pub(super) phase1: Phase1AdmissionKey,
    pub(super) decode_kind_mask: u32,
    pub(super) decode_candidate_count_bucket: u8,
    pub(super) decode_candidate_bytes_bucket: u8,
    pub(super) decode_unknown: bool,
    pub(super) source_class_hash: u64,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Phase1AdmissionKey {
    pub(super) alphabet_rejected_chunks_bucket: u8,
    pub(super) alphabet_rejected_bytes_bucket: u8,
    pub(super) bigram_rejected_chunks_bucket: u8,
    pub(super) bigram_rejected_bytes_bucket: u8,
    pub(super) admitted_chunks_bucket: u8,
    pub(super) admitted_bytes_bucket: u8,
}

impl Phase1AdmissionKey {
    fn from_summary(summary: Phase1AdmissionSummary) -> Self {
        Self {
            alphabet_rejected_chunks_bucket: autoroute_stable_bucket(
                summary.alphabet_rejected_chunks,
            ),
            alphabet_rejected_bytes_bucket: autoroute_stable_bucket(
                summary.alphabet_rejected_bytes,
            ),
            bigram_rejected_chunks_bucket: autoroute_stable_bucket(summary.bigram_rejected_chunks),
            bigram_rejected_bytes_bucket: autoroute_stable_bucket(summary.bigram_rejected_bytes),
            admitted_chunks_bucket: autoroute_stable_bucket(summary.admitted_chunks),
            admitted_bytes_bucket: autoroute_stable_bucket(summary.admitted_bytes),
        }
    }
}

/// Render a bucket identically in fail-closed routing errors and cache
/// inspection, so operators can match a refused workload field-for-field.
pub(super) fn render_workload_key(key: &WorkloadKey) -> String {
    format!(
        "bytes_log2={} chunks_log2={} max_file_log2={} patterns_log2={} \
         phase1_alphabet_rejected_chunks_log2={} phase1_alphabet_rejected_bytes_log2={} \
         phase1_bigram_rejected_chunks_log2={} phase1_bigram_rejected_bytes_log2={} \
         phase1_admitted_chunks_log2={} phase1_admitted_bytes_log2={} \
         decode_kinds={:08x} decode_candidates_log2={} decode_bytes_log2={} \
         decode_unknown={} source_hash={:016x}",
        key.bytes_bucket,
        key.chunks_bucket,
        key.max_file_bucket,
        key.pattern_bucket,
        key.phase1.alphabet_rejected_chunks_bucket,
        key.phase1.alphabet_rejected_bytes_bucket,
        key.phase1.bigram_rejected_chunks_bucket,
        key.phase1.bigram_rejected_bytes_bucket,
        key.phase1.admitted_chunks_bucket,
        key.phase1.admitted_bytes_bucket,
        key.decode_kind_mask,
        key.decode_candidate_count_bucket,
        key.decode_candidate_bytes_bucket,
        key.decode_unknown,
        key.source_class_hash
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WorkloadClassificationError {
    MissingSourceFamily {
        source_type: String,
        path: Option<String>,
    },
    DecodeSketchSampleBudgetExceeded {
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
            Self::DecodeSketchSampleBudgetExceeded {
                minimum_sample_bytes,
                chunk_count,
            } => write!(
                f,
                "autoroute cannot classify decoder work for {chunk_count} chunks within its {}-byte sampling cap: representative coverage requires at least {minimum_sample_bytes} bytes; lower --fused-batch or [scan].fused_batch and recalibrate",
                AUTOROUTE_DECODE_SAMPLE_BYTES
            ),
        }
    }
}

impl std::error::Error for WorkloadClassificationError {}

pub(super) fn workload_key(
    batch: &[Chunk],
    pattern_count: usize,
    phase1_admission: Phase1AdmissionSummary,
    decode_plan: DecodeWorkloadPlan,
) -> Result<WorkloadKey, WorkloadClassificationError> {
    let bytes: u64 = batch.iter().map(|c| c.data.len() as u64).sum();
    let max_file = batch
        .iter()
        .map(|c| c.metadata.size_bytes.unwrap_or(c.data.len() as u64)) // LAW10: empty/absent => documented numeric default, recall-safe
        .max()
        .unwrap_or(0); // LAW10: empty/absent => documented numeric default, recall-safe
    let decode = decode_workload_sketch(batch, decode_plan)?;
    let (
        decode_kind_mask,
        decode_candidate_count_bucket,
        decode_candidate_bytes_bucket,
        decode_unknown,
    ) = decode_workload_projection(decode);
    Ok(WorkloadKey {
        bytes_bucket: autoroute_stable_bucket(bytes),
        chunks_bucket: autoroute_stable_bucket(batch.len() as u64),
        max_file_bucket: autoroute_stable_bucket(max_file),
        pattern_bucket: log2_bucket(pattern_count as u64),
        phase1: Phase1AdmissionKey::from_summary(phase1_admission),
        decode_kind_mask,
        decode_candidate_count_bucket,
        decode_candidate_bytes_bucket,
        decode_unknown,
        source_class_hash: source_class_hash(batch)?,
    })
}

pub(super) fn decode_workload_projection(sketch: DecodeAdmissionSketch) -> (u32, u8, u8, bool) {
    (
        sketch.kind_mask(),
        autoroute_stable_decode_bucket(log2_bucket(u64::from(sketch.candidate_count()))),
        autoroute_stable_decode_bucket(log2_bucket(u64::from(sketch.candidate_bytes()))),
        sketch.has_unknown(),
    )
}

pub(super) fn autoroute_stable_bucket(value: u64) -> u8 {
    log2_bucket(value)
}

pub(super) fn autoroute_stable_decode_bucket(raw_bucket: u8) -> u8 {
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

// Every non-short chunk gets three bounded decoder-grammar windows. The
// remaining fixed budget is divided by bytes, without order or ties.
fn decode_sample_plan(
    batch: &[Chunk],
    decode_plan: DecodeWorkloadPlan,
) -> Result<DecodeSamplePlan, WorkloadClassificationError> {
    let mut base_bytes = 0usize;
    let mut residual_bytes = 0u128;
    let mut chunk_count = 0usize;

    for chunk in batch {
        if !decode_plan.admits(chunk) {
            continue;
        }
        let len = chunk.data.len();
        if len == 0 {
            continue;
        }
        chunk_count += 1;
        base_bytes = base_bytes.saturating_add(len.min(AUTOROUTE_DECODE_MIN_CHUNK_SAMPLE));
        residual_bytes += (len - len.min(AUTOROUTE_DECODE_MIN_CHUNK_SAMPLE)) as u128;
    }
    if base_bytes > AUTOROUTE_DECODE_SAMPLE_BYTES {
        return Err(
            WorkloadClassificationError::DecodeSketchSampleBudgetExceeded {
                minimum_sample_bytes: base_bytes,
                chunk_count,
            },
        );
    }
    let remaining = AUTOROUTE_DECODE_SAMPLE_BYTES - base_bytes;
    Ok(DecodeSamplePlan {
        residual_bytes,
        extra_bytes: (remaining as u128).min(residual_bytes),
    })
}

pub(super) fn decode_workload_sketch(
    batch: &[Chunk],
    decode_plan: DecodeWorkloadPlan,
) -> Result<DecodeAdmissionSketch, WorkloadClassificationError> {
    if !decode_plan.enabled() {
        return Ok(DecodeAdmissionSketch::NONE);
    }
    let plan = decode_sample_plan(batch, decode_plan)?;
    let mut sampled = 0usize;
    let mut sketch = DecodeAdmissionSketch::NONE;

    for chunk in batch {
        if !decode_plan.admits(chunk) {
            continue;
        }
        let bytes = chunk.data.as_bytes();
        let quota = plan.quota(bytes.len());
        for_each_decode_sample_window(bytes, quota, |window| {
            sampled = sampled.saturating_add(window.len());
            let sampled_chunk = Chunk {
                data: String::from_utf8_lossy(window).into_owned().into(),
                metadata: chunk.metadata.clone(),
            };
            sketch.merge(decode_plan.sketch(&sampled_chunk));
        });
    }
    debug_assert!(sampled <= AUTOROUTE_DECODE_SAMPLE_BYTES);
    Ok(sketch)
}

fn for_each_decode_sample_window(bytes: &[u8], quota: usize, mut visit: impl FnMut(&[u8])) {
    if quota == 0 {
        return;
    }
    if quota >= bytes.len() {
        visit(bytes);
        return;
    }

    let strata = AUTOROUTE_DECODE_SAMPLE_STRATA.min(quota / AUTOROUTE_DECODE_SAMPLE_WINDOW_BYTES);
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

#[cfg(test)]
pub(super) fn planned_decode_sample_bytes(
    batch: &[Chunk],
) -> Result<usize, WorkloadClassificationError> {
    let plan = decode_sample_plan(batch, DecodeWorkloadPlan::from_limits(1, usize::MAX))?;
    Ok(batch.iter().map(|chunk| plan.quota(chunk.data.len())).sum())
}

#[cfg(test)]
pub(super) fn planned_decode_sample_quotas(
    batch: &[Chunk],
) -> Result<Vec<usize>, WorkloadClassificationError> {
    let plan = decode_sample_plan(batch, DecodeWorkloadPlan::from_limits(1, usize::MAX))?;
    Ok(batch
        .iter()
        .map(|chunk| plan.quota(chunk.data.len()))
        .collect())
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
