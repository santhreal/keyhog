//! Autoroute workload bucketing and source-shape fingerprints.

use keyhog_core::Chunk;
use keyhog_scanner::decode::{DecodeAdmissionSketch, DecodeWorkloadPlan};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::LazyLock;

const AUTOROUTE_DECODE_SAMPLE_BYTES: usize = 64 * 1024;
const AUTOROUTE_DECODE_SAMPLE_WINDOW_BYTES: usize = 64;
const AUTOROUTE_DECODE_SAMPLE_STRATA: usize = 16;
const AUTOROUTE_DECODE_MIN_STRATA: usize = 3;
const AUTOROUTE_DECODE_MIN_CHUNK_SAMPLE: usize =
    AUTOROUTE_DECODE_SAMPLE_WINDOW_BYTES * AUTOROUTE_DECODE_MIN_STRATA;
const MAX_SOURCE_MIXTURE_ENTRIES: usize = 64;
pub(super) const MEASUREMENT_SHAPE_GENERATOR: &str = "keyhog-content-addressed-batch-v1";
const BUNDLED_SOURCE_CLASSES: &str = include_str!("../../../../data/autoroute_source_classes.toml");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceClassCatalogFile {
    source_classes: SourceClassCatalog,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceClassCatalog {
    classes: Vec<String>,
}

static CANONICAL_SOURCE_CLASSES: LazyLock<BTreeMap<[u8; 32], String>> = LazyLock::new(|| {
    let catalog: SourceClassCatalogFile = toml::from_str(BUNDLED_SOURCE_CLASSES)
        // LAW10: fail-closed; malformed embedded routing data aborts initialization, and no heuristic catalog is substituted.
        .unwrap_or_else(|error| panic!("data/autoroute_source_classes.toml is invalid: {error}"));
    validate_source_class_catalog(&catalog.source_classes.classes)
        // LAW10: fail-closed; semantically invalid routing data aborts initialization, and no heuristic catalog is substituted.
        .unwrap_or_else(|error| panic!("data/autoroute_source_classes.toml is invalid: {error}"));
    catalog
        .source_classes
        .classes
        .into_iter()
        .map(|class| (source_class_id(&class), class))
        .collect()
});

fn validate_source_class_catalog(classes: &[String]) -> Result<(), String> {
    if classes.is_empty() {
        return Err("source_classes.classes must not be empty".into());
    }
    let mut prior: Option<&str> = None;
    let mut digests = std::collections::HashSet::with_capacity(classes.len());
    for class in classes {
        if class.is_empty()
            || class.len() > 64
            || !class.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'/')
            })
        {
            return Err(format!(
                "source class {class:?} must contain 1..=64 ASCII identifier bytes"
            ));
        }
        if prior.is_some_and(|previous| previous >= class.as_str()) {
            return Err(format!(
                "source class {class:?} is duplicated or not bytewise sorted"
            ));
        }
        if !digests.insert(source_class_id(class)) {
            return Err(format!("source class {class:?} has a digest collision"));
        }
        prior = Some(class);
    }
    Ok(())
}

pub(super) fn source_class_label(digest: &[u8; 32]) -> Option<&'static str> {
    CANONICAL_SOURCE_CLASSES.get(digest).map(String::as_str)
}
pub(crate) fn canonical_source_classes() -> impl ExactSizeIterator<Item = &'static str> {
    CANONICAL_SOURCE_CLASSES.values().map(String::as_str)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SourceRouteClass {
    source_class_digest: [u8; 32],
    has_full_size: bool,
}

// `Ord` gives the multi-config cache a deterministic on-disk decision order
// (decisions are collected through a `BTreeMap<WorkloadKey, _>` on save), so a
// recalibration that re-measures the same buckets produces a byte-stable file.
//
// EVERY dimension here must be one calibration can enumerate ahead of time.
// The key used to also carry phase-1 admission counts, phase-2 keyword trigger
// counts, decode candidate counts, and per-source chunk/payload ratios. Those
// are measurements OF the bytes being scanned, not properties of the workload
// class, so a real scan produced a bucket the probe ladder had never generated
// and lookup, which is exact-match, failed closed with exit 2. Adding one file
// to a directory moved several of them at once. They stay in the recorded
// evidence of each measured point, where they describe what was measured; they
// do not decide which measurement applies.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkloadKey {
    pub(super) bytes_bucket: u8,
    pub(super) chunks_bucket: u8,
    pub(super) max_file_bucket: u8,
    pub(super) pattern_bucket: u8,
    /// Whether this workload does any decoder work at all.
    ///
    /// This was a 14-bit mask of exactly which decoder families the sampled
    /// bytes contained, plus an unknown-decoder flag. A 117-byte `.env` file
    /// produced mask `0x00000401`; the probe ladder generates its own text and
    /// produces mask `0`, so the two never met and the scan failed closed. The
    /// ladder can enumerate two states, decode work or none, and it already
    /// measures both through its `decode_heavy` probes. It cannot enumerate
    /// 16384 combinations of what a caller's files happen to contain.
    pub(super) decode_admitted: bool,
    pub(super) source_mixture: SourceMixtureKey,
}

/// Secret-safe identity for the exact batch that produced one timing point.
///
/// The workload key intentionally groups nearby workloads. This receipt keeps
/// distinct same-sized representatives inside that group from overwriting one
/// another while persisting no source text or paths.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MeasurementShapeEvidence {
    pub(super) generator: String,
    pub(super) payload_digest: [u8; 32],
    pub(super) shape_digest: [u8; 32],
}

/// Return the exact workload dimensions that differ between two route keys.
/// This is diagnostic-only and never participates in route selection.
pub(super) fn differing_workload_dimensions(
    requested: &WorkloadKey,
    calibrated: &WorkloadKey,
) -> Vec<&'static str> {
    let mut dimensions = Vec::new();
    if requested.bytes_bucket != calibrated.bytes_bucket {
        dimensions.push("bytes_bucket");
    }
    if requested.chunks_bucket != calibrated.chunks_bucket {
        dimensions.push("chunks_bucket");
    }
    if requested.max_file_bucket != calibrated.max_file_bucket {
        dimensions.push("max_file_bucket");
    }
    if requested.pattern_bucket != calibrated.pattern_bucket {
        dimensions.push("pattern_bucket");
    }
    if requested.decode_admitted != calibrated.decode_admitted {
        dimensions.push("decode_admitted");
    }
    if requested.source_mixture != calibrated.source_mixture {
        dimensions.push("source_mixture");
    }
    dimensions
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceMixtureKey {
    pub(super) entries: Vec<SourceMixtureEntry>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceMixtureEntry {
    pub(super) source_class_digest: [u8; 32],
    pub(super) has_full_size: bool,
}

/// Render a bucket identically in fail-closed routing errors and cache
/// inspection, so operators can match a refused workload field-for-field.
pub(super) fn render_workload_key(key: &WorkloadKey) -> String {
    let source_mixture = key
        .source_mixture
        .entries
        .iter()
        .map(|entry| {
            let digest = keyhog_core::hex_encode(&entry.source_class_digest);
            let source_class = source_class_label(&entry.source_class_digest).map_or_else(
                || format!("custom@{digest}"),
                |class| format!("{class}@{digest}"),
            );
            format!(
                "{}/{}",
                source_class,
                if entry.has_full_size {
                    "full"
                } else {
                    "payload"
                }
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "bytes_log2={} chunks_log2={} max_file_log2={} patterns_log2={} \
         decode_admitted={} source_mixture=[{}]",
        key.bytes_bucket,
        key.chunks_bucket,
        key.max_file_bucket,
        key.pattern_bucket,
        key.decode_admitted,
        source_mixture
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WorkloadClassificationError {
    MissingSourceClass {
        source_type: String,
        path: Option<String>,
    },
    TooManySourceMixtureEntries {
        entries: usize,
    },
    EmptySourceMixture,
    SourceClassIdentityCollision,
}

impl WorkloadClassificationError {
    fn missing_source_class(chunk: &Chunk) -> Self {
        Self::MissingSourceClass {
            source_type: chunk.metadata.source_type.to_string(),
            path: chunk.metadata.path.as_deref().map(|s| s.to_string()),
        }
    }
}

impl fmt::Display for WorkloadClassificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSourceClass {
                source_type,
                path: Some(path),
            } => write!(
                f,
                "chunk at {path} has invalid source_type {source_type:?}; every autorouted chunk must carry a non-empty source execution class"
            ),
            Self::MissingSourceClass {
                source_type,
                path: None,
            } => write!(
                f,
                "chunk has invalid source_type {source_type:?}; every autorouted chunk must carry a non-empty source execution class"
            ),
            Self::TooManySourceMixtureEntries { entries } => write!(
                f,
                "autoroute source mixture has {entries} distinct class/provenance entries, above the bounded limit of {MAX_SOURCE_MIXTURE_ENTRIES}; lower --fused-batch or choose an explicit backend and calibrate a smaller workload"
            ),
            Self::EmptySourceMixture => write!(
                f,
                "autoroute source mixture is empty; route a non-empty batch or choose an explicit backend for diagnostics"
            ),
            Self::SourceClassIdentityCollision => write!(
                f,
                "autoroute source-class identities collided after hashing; no routing decision can be trusted for this batch"
            ),
        }
    }
}

impl std::error::Error for WorkloadClassificationError {}

pub(super) fn workload_key(
    batch: &[Chunk],
    pattern_count: usize,
    decode_plan: DecodeWorkloadPlan,
) -> Result<WorkloadKey, WorkloadClassificationError> {
    let bytes: u64 = batch.iter().map(|c| c.data.len() as u64).sum();
    let max_file = batch
        .iter()
        .map(|c| c.metadata.size_bytes.unwrap_or(c.data.len() as u64)) // LAW10: empty/absent => documented numeric default, recall-safe
        .max()
        .unwrap_or(0); // LAW10: empty/absent => documented numeric default, recall-safe
    let decode = decode_workload_sketch(batch, decode_plan);
    let decode_admitted = decode_workload_projection(decode);
    Ok(WorkloadKey {
        bytes_bucket: autoroute_stable_bucket(bytes),
        chunks_bucket: autoroute_stable_bucket(batch.len() as u64),
        max_file_bucket: autoroute_stable_bucket(max_file),
        pattern_bucket: log2_bucket(pattern_count as u64),
        decode_admitted,
        source_mixture: source_mixture_key(batch)?,
    })
}

/// Does this batch do any decoder work? An unknown decoder kind still counts
/// as work, so it folds into the same flag rather than forming a third state.
pub(super) fn decode_workload_projection(sketch: DecodeAdmissionSketch) -> bool {
    sketch.kind_mask() != 0 || sketch.has_unknown()
}

pub(super) fn autoroute_stable_bucket(value: u64) -> u8 {
    log2_bucket(value)
}

#[derive(Clone, Copy)]
struct DecodeSamplePlan {
    residual_bytes: u128,
    extra_bytes: u128,
    /// What the plan may sample in total, so the sketch can assert it stayed
    /// inside the budget it was actually given rather than a fixed constant.
    budget_bytes: usize,
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

/// The sampling budget for one batch.
///
/// Every admitted chunk gets a floor of `AUTOROUTE_DECODE_MIN_CHUNK_SAMPLE`
/// bytes so no chunk goes unclassified; `AUTOROUTE_DECODE_SAMPLE_BYTES` is the
/// budget for the residual sampling layered on top of that floor.
///
/// It used to be read as a ceiling on the total, and that made a legal
/// production batch unclassifiable: the coalesced pipeline packs up to 4,096
/// chunks, whose floors alone need 786 KiB, so classification failed outright
/// above roughly 341 non-trivial chunks. Autoroute calibration therefore could
/// not run through `--batch-pipeline` on any real corpus, and since the GPU
/// route only runs through that pipeline, GPU could not be calibrated at all.
///
/// Raising the floor is a pure extension. A batch whose floors already fit
/// keeps exactly today's residual budget, so its sketch, its workload key and
/// every persisted decision are unchanged. A batch that used to fail now gets
/// floor-only sampling: one bounded window set per chunk, uniform across the
/// whole batch, and more total sample than any batch that succeeds today.
/// The cost is bounded by the batch itself, since the floor never exceeds a
/// chunk's own length.
fn decode_sample_budget(base_bytes: usize) -> usize {
    base_bytes.max(AUTOROUTE_DECODE_SAMPLE_BYTES)
}

#[cfg(test)]
pub(super) fn decode_sample_budget_for_test(base_bytes: usize) -> usize {
    decode_sample_budget(base_bytes)
}

// Every non-short chunk gets three bounded decoder-grammar windows. The
// remaining fixed budget is divided by bytes, without order or ties.
fn decode_sample_plan(batch: &[Chunk], decode_plan: DecodeWorkloadPlan) -> DecodeSamplePlan {
    let mut base_bytes = 0usize;
    let mut residual_bytes = 0u128;

    for chunk in batch {
        if !decode_plan.admits(chunk) {
            continue;
        }
        let len = chunk.data.len();
        if len == 0 {
            continue;
        }
        base_bytes = base_bytes.saturating_add(len.min(AUTOROUTE_DECODE_MIN_CHUNK_SAMPLE));
        residual_bytes += (len - len.min(AUTOROUTE_DECODE_MIN_CHUNK_SAMPLE)) as u128;
    }
    let remaining = decode_sample_budget(base_bytes) - base_bytes;
    DecodeSamplePlan {
        residual_bytes,
        extra_bytes: (remaining as u128).min(residual_bytes),
        budget_bytes: decode_sample_budget(base_bytes),
    }
}

pub(super) fn decode_workload_sketch(
    batch: &[Chunk],
    decode_plan: DecodeWorkloadPlan,
) -> DecodeAdmissionSketch {
    if !decode_plan.enabled() {
        return DecodeAdmissionSketch::NONE;
    }
    let plan = decode_sample_plan(batch, decode_plan.clone());
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
    debug_assert!(sampled <= plan.budget_bytes);
    sketch
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
pub(super) fn planned_decode_sample_bytes(batch: &[Chunk]) -> usize {
    let plan = decode_sample_plan(batch, DecodeWorkloadPlan::from_limits(1, usize::MAX));
    batch.iter().map(|chunk| plan.quota(chunk.data.len())).sum()
}

#[cfg(test)]
pub(super) fn planned_decode_sample_quotas(batch: &[Chunk]) -> Vec<usize> {
    let plan = decode_sample_plan(batch, DecodeWorkloadPlan::from_limits(1, usize::MAX));
    batch
        .iter()
        .map(|chunk| plan.quota(chunk.data.len()))
        .collect()
}

pub(super) fn source_mixture_key(
    batch: &[Chunk],
) -> Result<SourceMixtureKey, WorkloadClassificationError> {
    if batch.is_empty() {
        return Err(WorkloadClassificationError::EmptySourceMixture);
    }
    // `size_bytes` is the original backing-source size; its absence means the
    // max-size bucket was derived from a stream or transformed payload. Bind
    // that provenance to each source class so numerically equal buckets do
    // not reuse measurements made for a different kind of workload evidence.
    let mut classes: BTreeSet<(String, bool)> = BTreeSet::new();
    for chunk in batch {
        let source_class = source_execution_class(chunk)?.to_string();
        classes.insert((source_class, chunk.metadata.size_bytes.is_some()));
        if classes.len() > MAX_SOURCE_MIXTURE_ENTRIES {
            return Err(WorkloadClassificationError::TooManySourceMixtureEntries {
                entries: classes.len(),
            });
        }
    }
    let mut entries = classes
        .into_iter()
        .map(|(source_class, has_full_size)| SourceMixtureEntry {
            source_class_digest: source_class_id(source_class.as_str()),
            has_full_size,
        })
        .collect::<Vec<_>>();
    entries.sort_unstable();
    if entries.windows(2).any(|pair| {
        pair[0].source_class_digest == pair[1].source_class_digest
            && pair[0].has_full_size == pair[1].has_full_size
    }) {
        return Err(WorkloadClassificationError::SourceClassIdentityCollision);
    }
    Ok(SourceMixtureKey { entries })
}

pub(crate) fn source_route_class(chunk: &Chunk) -> Option<SourceRouteClass> {
    Some(SourceRouteClass {
        source_class_digest: source_class_id(source_execution_class(chunk).ok()?), // LAW10: optional pre-batch split probe; authoritative workload classification returns the source error
        has_full_size: chunk.metadata.size_bytes.is_some(),
    })
}

pub(super) fn source_class_id(source_class: &str) -> [u8; 32] {
    let mut hasher = crate::stable_hash::StableHasher::new("autoroute-source-class-v1");
    hasher.field_str("source_class", source_class);
    hasher.finish_256()
}

pub(super) fn workload_evidence_digest(key: &WorkloadKey) -> [u8; 32] {
    let mut hasher = crate::stable_hash::StableHasher::new("autoroute-workload-evidence-v1");
    hasher
        .field_u64("bytes_bucket", u64::from(key.bytes_bucket))
        .field_u64("chunks_bucket", u64::from(key.chunks_bucket))
        .field_u64("max_file_bucket", u64::from(key.max_file_bucket))
        .field_u64("pattern_bucket", u64::from(key.pattern_bucket))
        .field_bool("decode_admitted", key.decode_admitted)
        .field_usize("source_mixture.entries", key.source_mixture.entries.len());
    for (index, entry) in key.source_mixture.entries.iter().enumerate() {
        hasher
            .field_usize("source_mixture.index", index)
            .field_bytes(
                "source_mixture.source_class_digest",
                &entry.source_class_digest,
            )
            .field_bool("source_mixture.has_full_size", entry.has_full_size);
    }
    hasher.finish_256()
}

pub(super) fn measurement_shape_evidence(
    batch: &[Chunk],
) -> Result<MeasurementShapeEvidence, WorkloadClassificationError> {
    let mut payloads = Vec::with_capacity(batch.len());
    let mut shapes = Vec::with_capacity(batch.len());
    for chunk in batch {
        let source_class = source_execution_class(chunk)?;
        let mut payload_hasher =
            crate::stable_hash::StableHasher::new("autoroute-measured-chunk-payload-v1");
        payload_hasher
            .field_usize("payload_bytes", chunk.data.len())
            .field_bytes("payload", chunk.data.as_bytes());
        let payload_digest = payload_hasher.finish_256();
        payloads.push((chunk.data.len(), payload_digest));

        let mut shape_hasher =
            crate::stable_hash::StableHasher::new("autoroute-measured-chunk-shape-v1");
        shape_hasher
            .field_str("source_class", source_class)
            .field_usize("payload_bytes", chunk.data.len())
            .field_option_u64("source_bytes", chunk.metadata.size_bytes)
            .field_usize("base_offset", chunk.metadata.base_offset)
            .field_usize("base_line", chunk.metadata.base_line)
            .field_bytes("payload_digest", &payload_digest);
        match chunk.metadata.decoded_span {
            Some((start, end)) => {
                shape_hasher
                    .field_bool("decoded_span.present", true)
                    .field_usize("decoded_span.start", start)
                    .field_usize("decoded_span.end", end);
            }
            None => {
                shape_hasher.field_bool("decoded_span.present", false);
            }
        }
        shapes.push(shape_hasher.finish_256());
    }
    payloads.sort_unstable();
    shapes.sort_unstable();

    let mut payload_hasher =
        crate::stable_hash::StableHasher::new("autoroute-measured-batch-payload-v1");
    payload_hasher.field_usize("chunks", payloads.len());
    for (index, (bytes, digest)) in payloads.iter().enumerate() {
        payload_hasher
            .field_usize("chunk.index", index)
            .field_usize("chunk.bytes", *bytes)
            .field_bytes("chunk.payload_digest", digest);
    }
    let payload_digest = payload_hasher.finish_256();

    let mut shape_hasher =
        crate::stable_hash::StableHasher::new("autoroute-measured-batch-shape-v1");
    shape_hasher
        .field_str("generator", MEASUREMENT_SHAPE_GENERATOR)
        .field_usize("chunks", shapes.len())
        .field_bytes("payload_digest", &payload_digest);
    for (index, digest) in shapes.iter().enumerate() {
        shape_hasher
            .field_usize("chunk.index", index)
            .field_bytes("chunk.shape_digest", digest);
    }
    Ok(MeasurementShapeEvidence {
        generator: MEASUREMENT_SHAPE_GENERATOR.to_string(),
        payload_digest,
        shape_digest: shape_hasher.finish_256(),
    })
}

pub(super) fn validate_measurement_shape_evidence(
    evidence: &MeasurementShapeEvidence,
) -> Result<(), String> {
    if evidence.generator != MEASUREMENT_SHAPE_GENERATOR {
        return Err(format!(
            "measurement point uses unsupported probe generator {:?}; expected {MEASUREMENT_SHAPE_GENERATOR:?}",
            evidence.generator
        ));
    }
    if evidence.payload_digest == [0; 32] || evidence.shape_digest == [0; 32] {
        return Err("measurement point contains an empty payload or shape digest".into());
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn test_measurement_shape_evidence(
    sample_bytes: u64,
    sample_chunks: usize,
) -> MeasurementShapeEvidence {
    let mut payload = crate::stable_hash::StableHasher::new("autoroute-test-payload-v1");
    payload
        .field_u64("sample_bytes", sample_bytes)
        .field_usize("sample_chunks", sample_chunks);
    let payload_digest = payload.finish_256();
    let mut shape = crate::stable_hash::StableHasher::new("autoroute-test-shape-v1");
    shape
        .field_str("generator", MEASUREMENT_SHAPE_GENERATOR)
        .field_bytes("payload_digest", &payload_digest);
    MeasurementShapeEvidence {
        generator: MEASUREMENT_SHAPE_GENERATOR.to_string(),
        payload_digest,
        shape_digest: shape.finish_256(),
    }
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
        let identity = (entry.source_class_digest, entry.has_full_size);
        if previous.is_some_and(|prior| prior >= identity) {
            return Err(
                "source mixture entries are duplicate or not canonically sorted".to_string(),
            );
        }
        previous = Some(identity);
    }
    Ok(())
}

pub(super) fn validate_workload_source_mixture(key: &WorkloadKey) -> Result<(), String> {
    validate_workload_buckets(key)?;
    validate_source_mixture_key(&key.source_mixture)
}

fn validate_workload_buckets(key: &WorkloadKey) -> Result<(), String> {
    let max_u64_bucket = log2_bucket(u64::MAX);
    let scalar_buckets = [
        ("bytes", key.bytes_bucket),
        ("chunks", key.chunks_bucket),
        ("max_file", key.max_file_bucket),
        ("patterns", key.pattern_bucket),
    ];
    if let Some((name, bucket)) = scalar_buckets
        .into_iter()
        .find(|(_, bucket)| *bucket > max_u64_bucket)
    {
        return Err(format!(
            "workload {name} bucket {bucket} exceeds the maximum logarithmic bucket {max_u64_bucket}"
        ));
    }
    if key.bytes_bucket == 0 || key.chunks_bucket == 0 {
        return Err(
            "workload byte and chunk buckets must describe non-empty calibration input".into(),
        );
    }
    Ok(())
}

fn source_execution_class(chunk: &Chunk) -> Result<&str, WorkloadClassificationError> {
    let source_type = chunk.metadata.source_type.trim();
    if source_type.is_empty() {
        return Err(WorkloadClassificationError::missing_source_class(chunk));
    }
    for (dynamic_prefix, canonical_class) in [
        ("binary:elf:", "binary:elf"),
        ("binary:pe:", "binary:pe"),
        ("binary:macho:", "binary:macho"),
        ("filesystem/image-metadata/", "filesystem/image-metadata"),
    ] {
        if source_type.starts_with(dynamic_prefix) {
            return Ok(canonical_class);
        }
    }
    Ok(source_type)
}

pub(super) fn log2_bucket(value: u64) -> u8 {
    if value == 0 {
        0
    } else {
        (u64::BITS - value.leading_zeros()) as u8
    }
}
