//! Autoroute workload bucketing and source-shape fingerprints.

use keyhog_core::Chunk;
use keyhog_scanner::decode::{DecodeAdmissionSketch, DecodeWorkloadPlan};
use keyhog_scanner::Phase1AdmissionSummary;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

const AUTOROUTE_DECODE_SAMPLE_BYTES: usize = 64 * 1024;
const AUTOROUTE_DECODE_SAMPLE_WINDOW_BYTES: usize = 64;
const AUTOROUTE_DECODE_SAMPLE_STRATA: usize = 16;
const AUTOROUTE_DECODE_MIN_STRATA: usize = 3;
const AUTOROUTE_DECODE_MIN_CHUNK_SAMPLE: usize =
    AUTOROUTE_DECODE_SAMPLE_WINDOW_BYTES * AUTOROUTE_DECODE_MIN_STRATA;
const MAX_SOURCE_MIXTURE_ENTRIES: usize = 64;

// `Ord` gives the multi-config cache a deterministic on-disk decision order
// (decisions are collected through a `BTreeMap<WorkloadKey, _>` on save), so a
// recalibration that re-measures the same buckets produces a byte-stable file.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
    pub(super) source_mixture: SourceMixtureKey,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceMixtureKey {
    pub(super) entries: Vec<SourceMixtureEntry>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceMixtureEntry {
    pub(super) family_digest: [u8; 32],
    pub(super) has_full_size: bool,
    pub(super) chunk_ratio: u64,
    pub(super) payload_ratio: u64,
    pub(super) max_span_bucket: u8,
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
    let source_mixture = key
        .source_mixture
        .entries
        .iter()
        .map(|entry| {
            format!(
                "{}/{}/chunk_ratio={}/payload_ratio={}/max_span_log2={}",
                keyhog_core::hex_encode(&entry.family_digest),
                if entry.has_full_size {
                    "full"
                } else {
                    "payload"
                },
                entry.chunk_ratio,
                entry.payload_ratio,
                entry.max_span_bucket
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "bytes_log2={} chunks_log2={} max_file_log2={} patterns_log2={} \
         phase1_alphabet_rejected_chunks_log2={} phase1_alphabet_rejected_bytes_log2={} \
         phase1_bigram_rejected_chunks_log2={} phase1_bigram_rejected_bytes_log2={} \
         phase1_admitted_chunks_log2={} phase1_admitted_bytes_log2={} \
         decode_kinds={:08x} decode_candidates_log2={} decode_bytes_log2={} \
         decode_unknown={} source_mixture=[{}]",
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
        source_mixture
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
    TooManySourceMixtureEntries {
        entries: usize,
    },
    EmptySourceMixture,
    EmptySourcePayload,
    SourceFamilyIdentityCollision,
    SourceMixtureAccountingOverflow,
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
            Self::TooManySourceMixtureEntries { entries } => write!(
                f,
                "autoroute source mixture has {entries} distinct family/provenance entries, above the bounded limit of {MAX_SOURCE_MIXTURE_ENTRIES}; lower --fused-batch or choose an explicit backend and calibrate a smaller workload"
            ),
            Self::EmptySourceMixture => write!(
                f,
                "autoroute source mixture is empty; route a non-empty batch or choose an explicit backend for diagnostics"
            ),
            Self::EmptySourcePayload => write!(
                f,
                "autoroute source mixture contains no payload bytes; route a non-empty payload or choose an explicit backend for diagnostics"
            ),
            Self::SourceFamilyIdentityCollision => write!(
                f,
                "autoroute source-family identities collided after hashing; no routing decision can be trusted for this batch"
            ),
            Self::SourceMixtureAccountingOverflow => write!(
                f,
                "autoroute source-mixture accounting exceeds the supported u64 range; lower --fused-batch and recalibrate"
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
        source_mixture: source_mixture_key(batch)?,
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

pub(super) fn source_mixture_key(
    batch: &[Chunk],
) -> Result<SourceMixtureKey, WorkloadClassificationError> {
    if batch.is_empty() {
        return Err(WorkloadClassificationError::EmptySourceMixture);
    }
    // `size_bytes` is the original backing-source size; its absence means the
    // max-size bucket was derived from a stream or transformed payload. Bind
    // that provenance to each source family so numerically equal buckets do
    // not reuse measurements made for a different kind of workload evidence.
    let mut classes: BTreeMap<(String, bool), (u64, u64, u64)> = BTreeMap::new();
    for chunk in batch {
        let family = source_family(chunk)?.to_string();
        let has_full_size = chunk.metadata.size_bytes.is_some();
        let payload_bytes = chunk.data.len() as u64;
        let span = chunk.metadata.size_bytes.unwrap_or(payload_bytes);
        let entry = classes.entry((family, has_full_size)).or_default();
        entry.0 = entry
            .0
            .checked_add(1)
            .ok_or(WorkloadClassificationError::SourceMixtureAccountingOverflow)?;
        entry.1 = entry
            .1
            .checked_add(payload_bytes)
            .ok_or(WorkloadClassificationError::SourceMixtureAccountingOverflow)?;
        entry.2 = entry.2.max(span);
        if classes.len() > MAX_SOURCE_MIXTURE_ENTRIES {
            return Err(WorkloadClassificationError::TooManySourceMixtureEntries {
                entries: classes.len(),
            });
        }
    }
    let chunk_divisor = classes
        .values()
        .map(|(chunks, _, _)| *chunks)
        .reduce(greatest_common_divisor)
        .unwrap_or(1);
    let payload_divisor = classes
        .values()
        .map(|(_, payload_bytes, _)| *payload_bytes)
        .filter(|bytes| *bytes > 0)
        .reduce(greatest_common_divisor)
        .ok_or(WorkloadClassificationError::EmptySourcePayload)?;
    let mut entries = classes
        .into_iter()
        .map(
            |((family, has_full_size), (chunks, payload_bytes, max_span))| SourceMixtureEntry {
                family_digest: source_family_id(&family),
                has_full_size,
                chunk_ratio: chunks / chunk_divisor,
                payload_ratio: payload_bytes / payload_divisor,
                max_span_bucket: autoroute_stable_bucket(max_span),
            },
        )
        .collect::<Vec<_>>();
    entries.sort_unstable();
    if entries.windows(2).any(|pair| {
        pair[0].family_digest == pair[1].family_digest
            && pair[0].has_full_size == pair[1].has_full_size
    }) {
        return Err(WorkloadClassificationError::SourceFamilyIdentityCollision);
    }
    Ok(SourceMixtureKey { entries })
}

pub(super) fn source_family_id(family: &str) -> [u8; 32] {
    let mut hasher = crate::stable_hash::StableHasher::new("autoroute-source-family-v1");
    hasher.field_str("family", family);
    hasher.finish_256()
}

pub(super) fn validate_source_mixture_key(key: &SourceMixtureKey) -> Result<(), String> {
    if key.entries.is_empty() || key.entries.len() > MAX_SOURCE_MIXTURE_ENTRIES {
        return Err(format!(
            "source mixture has {} entries; expected 1..={MAX_SOURCE_MIXTURE_ENTRIES}",
            key.entries.len()
        ));
    }
    let mut previous: Option<([u8; 32], bool)> = None;
    for entry in &key.entries {
        let identity = (entry.family_digest, entry.has_full_size);
        if previous.is_some_and(|prior| prior >= identity) {
            return Err(
                "source mixture entries are duplicate or not canonically sorted".to_string(),
            );
        }
        if entry.chunk_ratio == 0
            || (!entry.has_full_size && entry.payload_ratio == 0 && entry.max_span_bucket > 0)
        {
            return Err(format!(
                "source mixture entry {} has an inconsistent chunk ratio, payload ratio, or span",
                keyhog_core::hex_encode(&entry.family_digest)
            ));
        }
        previous = Some(identity);
    }
    let chunk_divisor = key
        .entries
        .iter()
        .map(|entry| entry.chunk_ratio)
        .reduce(greatest_common_divisor)
        .unwrap_or(0);
    let payload_divisor = key
        .entries
        .iter()
        .map(|entry| entry.payload_ratio)
        .filter(|ratio| *ratio > 0)
        .reduce(greatest_common_divisor)
        .unwrap_or(0);
    if chunk_divisor != 1 || payload_divisor != 1 {
        return Err(
            "source mixture ratios are zero or not reduced to canonical lowest terms".into(),
        );
    }
    Ok(())
}

pub(super) fn validate_workload_source_mixture(key: &WorkloadKey) -> Result<(), String> {
    validate_source_mixture_key(&key.source_mixture)?;
    let max_span_bucket = key
        .source_mixture
        .entries
        .iter()
        .map(|entry| entry.max_span_bucket)
        .max()
        .unwrap_or(0);
    if max_span_bucket != key.max_file_bucket {
        return Err(
            "source mixture maximum span is inconsistent with the parent workload key".into(),
        );
    }
    if key
        .source_mixture
        .entries
        .iter()
        .all(|entry| !entry.has_full_size)
        && key.max_file_bucket > key.bytes_bucket
    {
        return Err("payload-derived source spans cannot exceed the aggregate payload band".into());
    }
    Ok(())
}

fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        (left, right) = (right, left % right);
    }
    left
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
