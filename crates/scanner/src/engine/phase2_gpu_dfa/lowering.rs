//! Regex-DFA shard construction and versioned coverage artifacts.

use super::{Phase2GpuDfaShard, PHASE2_GPU_DFA_MAX_STATES};
use crate::types::CompiledPattern;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// Every shard is a separate dispatch over the SAME haystack, so shard count
/// multiplies GPU work directly. A pool that shatters is not an accelerator,
/// it is a dispatch storm: the caller drops such a catalog and leaves CPU
/// admission authoritative rather than paying for it.
pub(super) const PHASE2_GPU_DFA_MAX_SHARDS: usize = 64;
pub(super) const PHASE2_GPU_DFA_MAX_AGGREGATE_STATES: usize = 262_144;
pub(super) const PHASE2_GPU_DFA_MAX_OUTPUT_RECORDS: usize = 1_048_576;
pub(super) const PHASE2_GPU_DFA_MAX_RESIDENT_BYTES: usize = 512 * 1024 * 1024;
const PHASE2_GPU_DFA_MAX_SOURCE_BYTES_PER_SHARD: usize = 8 * 1024 * 1024;

pub(super) fn validate_catalog_limits(shards: &[Phase2GpuDfaShard]) -> Result<(), String> {
    validate_catalog_totals(shards.len(), 0, 0, 0)?;
    let mut aggregate_states = 0usize;
    let mut aggregate_outputs = 0usize;
    let mut resident_bytes = 0usize;
    for (index, shard) in shards.iter().enumerate() {
        let state_count = shard.pipeline.dfa.state_count as usize;
        if state_count > PHASE2_GPU_DFA_MAX_STATES {
            return Err(format!(
                "phase-2 GPU DFA shard {index} state ceiling exceeded: {state_count} > {PHASE2_GPU_DFA_MAX_STATES}"
            ));
        }
        aggregate_states = aggregate_states
            .checked_add(state_count)
            .ok_or_else(|| "phase-2 GPU DFA aggregate state count overflow".to_string())?;
        aggregate_outputs = aggregate_outputs
            .checked_add(shard.pipeline.dfa.output_records.len())
            .ok_or_else(|| "phase-2 GPU DFA aggregate output count overflow".to_string())?;
        let shard_bytes = shard
            .pipeline
            .dfa
            .transitions
            .len()
            .checked_add(shard.pipeline.dfa.output_offsets.len())
            .and_then(|words| words.checked_add(shard.pipeline.dfa.output_records.len()))
            .and_then(|words| words.checked_mul(std::mem::size_of::<u32>()))
            .ok_or_else(|| "phase-2 GPU DFA resident byte count overflow".to_string())?;
        resident_bytes = resident_bytes
            .checked_add(shard_bytes)
            .ok_or_else(|| "phase-2 GPU DFA aggregate resident byte count overflow".to_string())?;
    }
    validate_catalog_totals(
        shards.len(),
        aggregate_states,
        aggregate_outputs,
        resident_bytes,
    )
}

pub(super) fn validate_catalog_totals(
    dispatches: usize,
    aggregate_states: usize,
    aggregate_outputs: usize,
    resident_bytes: usize,
) -> Result<(), String> {
    if dispatches > PHASE2_GPU_DFA_MAX_SHARDS {
        return Err(format!(
            "phase-2 GPU DFA dispatch ceiling exceeded: {dispatches} > {PHASE2_GPU_DFA_MAX_SHARDS}"
        ));
    }
    if aggregate_states > PHASE2_GPU_DFA_MAX_AGGREGATE_STATES {
        return Err(format!(
            "phase-2 GPU DFA aggregate state ceiling exceeded: {aggregate_states} > {PHASE2_GPU_DFA_MAX_AGGREGATE_STATES}"
        ));
    }
    if aggregate_outputs > PHASE2_GPU_DFA_MAX_OUTPUT_RECORDS {
        return Err(format!(
            "phase-2 GPU DFA output ceiling exceeded: {aggregate_outputs} > {PHASE2_GPU_DFA_MAX_OUTPUT_RECORDS}"
        ));
    }
    if resident_bytes > PHASE2_GPU_DFA_MAX_RESIDENT_BYTES {
        return Err(format!(
            "phase-2 GPU DFA resident-byte ceiling exceeded: {resident_bytes} > {PHASE2_GPU_DFA_MAX_RESIDENT_BYTES}"
        ));
    }
    Ok(())
}

pub(super) fn build_shards_recursive(
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
    indices: &[usize],
    use_subgroup_coalesce: bool,
    shards: &mut Vec<Phase2GpuDfaShard>,
    uncovered_patterns: &mut usize,
) {
    if indices.is_empty() {
        return;
    }
    // One uncovered pattern already forfeits the completeness the caller needs,
    // and splitting past the shard budget only deepens a dispatch storm the
    // caller will refuse anyway. Either way, stop and account the rest.
    if *uncovered_patterns > 0 || shards.len() >= PHASE2_GPU_DFA_MAX_SHARDS {
        *uncovered_patterns = uncovered_patterns.saturating_add(indices.len());
        return;
    }
    // Start with the complete candidate set. A successful compilation gives
    // one dispatch over the haystack; only an actual DFA/state-cap failure may
    // split it into more dispatches.
    match build_shard(phase2_patterns, indices, use_subgroup_coalesce) {
        Ok(shard) => {
            shards.push(shard);
        }
        Err(error) if indices.len() > 1 => {
            let mid = indices.len() / 2;
            build_shards_recursive(
                phase2_patterns,
                &indices[..mid],
                use_subgroup_coalesce,
                shards,
                uncovered_patterns,
            );
            build_shards_recursive(
                phase2_patterns,
                &indices[mid..],
                use_subgroup_coalesce,
                shards,
                uncovered_patterns,
            );
            tracing::debug!(
                target: "keyhog::gpu",
                patterns = indices.len(),
                %error,
                "phase-2 GPU regex-DFA shard split after compile failure"
            );
        }
        Err(error) => {
            *uncovered_patterns = uncovered_patterns.saturating_add(indices.len());
            tracing::warn!(
                target: "keyhog::gpu",
                phase2_index = indices[0],
                %error,
                "phase-2 prefixless pattern could not lower to GPU regex-DFA; CPU admission remains authoritative for it"
            );
        }
    }
}

pub(super) fn build_shard(
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
    indices: &[usize],
    use_subgroup_coalesce: bool,
) -> std::result::Result<Phase2GpuDfaShard, String> {
    let source_bytes = indices.iter().try_fold(0usize, |total, &idx| {
        let (pattern, _) = phase2_patterns
            .get(idx)
            .ok_or_else(|| format!("phase-2 index {idx} is out of range"))?;
        total
            .checked_add(pattern.regex.as_str().len())
            .ok_or_else(|| "phase-2 GPU DFA source byte count overflow".to_string())
    })?;
    if source_bytes > PHASE2_GPU_DFA_MAX_SOURCE_BYTES_PER_SHARD {
        return Err(format!(
            "phase-2 GPU DFA shard source ceiling exceeded: {source_bytes} > {PHASE2_GPU_DFA_MAX_SOURCE_BYTES_PER_SHARD}"
        ));
    }
    let mut sources = Vec::with_capacity(indices.len());
    for &idx in indices {
        let (pattern, _) = phase2_patterns
            .get(idx)
            .ok_or_else(|| format!("phase-2 index {idx} is out of range"))?;
        sources.push(regex_dfa_source_for_pattern(pattern));
    }
    let source_refs: Vec<&str> = sources.iter().map(|source| source.as_ref()).collect();
    // Region admission replays an anchored DFA once from each byte origin. An
    // implicit search prefix would rescan earlier bytes from every origin and
    // is only appropriate for the old match-triple materializer.
    let pipeline = vyre_libs::scan::regex_dfa::build_regex_dfa_pipeline_ext(
        &source_refs,
        1,
        PHASE2_GPU_DFA_MAX_STATES,
        use_subgroup_coalesce,
    )
    .map_err(|error| error.to_string())?;
    Ok(Phase2GpuDfaShard {
        pipeline,
        phase2_indices: indices.to_vec(),
    })
}

pub(super) fn regex_dfa_source_for_pattern(pattern: &CompiledPattern) -> Cow<'_, str> {
    let source = pattern.regex.as_str();
    if pattern.regex.is_case_insensitive() {
        let mut wrapped = String::with_capacity(source.len() + "(?i:)".len());
        wrapped.push_str("(?i:");
        wrapped.push_str(source);
        wrapped.push(')');
        Cow::Owned(wrapped)
    } else {
        Cow::Borrowed(source)
    }
}

pub(super) const PHASE2_GPU_DFA_ARTIFACT_VERSION: u32 = 1;
pub(super) const PHASE2_GPU_DFA_MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) enum CpuRequiredReason {
    KeywordGated,
    GatePrefixed,
    AsciiHomoglyphRedundant,
    LoweringUnsupported,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) enum PatternCoverageDisposition {
    GpuCovered { shard: u32 },
    CpuRequired(CpuRequiredReason),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PatternCoverageEvidence {
    pub(super) phase2_index: u32,
    pub(super) pattern_digest: [u8; 32],
    pub(super) disposition: PatternCoverageDisposition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Phase2GpuDfaArtifact {
    version: u32,
    detector_digest: [u8; 32],
    catalog_digest: [u8; 32],
    pub(super) entries: Vec<PatternCoverageEvidence>,
    pub(super) shards: Vec<Vec<u32>>,
}

impl Phase2GpuDfaArtifact {
    pub(super) fn build(
        detector_digest: [u8; 32],
        entries: Vec<PatternCoverageEvidence>,
        shards: Vec<Vec<u32>>,
    ) -> Result<Self, String> {
        let catalog_digest = digest_payload(detector_digest, &entries, &shards)?;
        Ok(Self {
            version: PHASE2_GPU_DFA_ARTIFACT_VERSION,
            detector_digest,
            catalog_digest,
            entries,
            shards,
        })
    }

    pub(super) fn catalog_digest(&self) -> [u8; 32] {
        self.catalog_digest
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec(self).map_err(|error| {
            format!("phase-2 GPU catalog artifact serialization failed: {error}")
        })?;
        if bytes.len() > PHASE2_GPU_DFA_MAX_ARTIFACT_BYTES {
            return Err(format!(
                "phase-2 GPU catalog artifact is {} byte(s), above the {}-byte ceiling",
                bytes.len(),
                PHASE2_GPU_DFA_MAX_ARTIFACT_BYTES
            ));
        }
        Ok(bytes)
    }

    pub(super) fn decode(bytes: &[u8], expected_detector_digest: [u8; 32]) -> Result<Self, String> {
        if bytes.len() > PHASE2_GPU_DFA_MAX_ARTIFACT_BYTES {
            return Err(format!(
                "phase-2 GPU catalog artifact is {} byte(s), above the {}-byte ceiling",
                bytes.len(),
                PHASE2_GPU_DFA_MAX_ARTIFACT_BYTES
            ));
        }
        let artifact: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("corrupt phase-2 GPU catalog artifact: {error}"))?;
        if artifact.version != PHASE2_GPU_DFA_ARTIFACT_VERSION {
            return Err(format!(
                "stale phase-2 GPU catalog artifact version {}; expected {}",
                artifact.version, PHASE2_GPU_DFA_ARTIFACT_VERSION
            ));
        }
        if artifact.detector_digest != expected_detector_digest {
            return Err("phase-2 GPU catalog detector digest mismatch".to_string());
        }
        let expected_catalog_digest = digest_payload(
            artifact.detector_digest,
            &artifact.entries,
            &artifact.shards,
        )?;
        if artifact.catalog_digest != expected_catalog_digest {
            return Err("corrupt phase-2 GPU catalog digest".to_string());
        }
        validate_complete_evidence(&artifact.entries, &artifact.shards)?;
        Ok(artifact)
    }
}

pub(super) fn pattern_digest(pattern: &CompiledPattern, keywords: &[String]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let source = pattern.regex.as_str();
    hasher.update(b"keyhog.phase2-gpu-dfa.pattern.v1\0");
    hasher.update(&(pattern.detector_index as u64).to_le_bytes());
    hasher.update(&(pattern.group.unwrap_or(usize::MAX) as u64).to_le_bytes());
    hasher.update(&[
        u8::from(pattern.regex.is_case_insensitive()),
        u8::from(pattern.client_safe),
        u8::from(pattern.weak_anchor),
        u8::from(pattern.structural_password_slot),
        u8::from(pattern.match_proves_keyword_nearby),
        u8::from(pattern.allows_repeated_keyword_separator),
        u8::from(pattern.homoglyph_variant),
    ]);
    hasher.update(&(source.len() as u64).to_le_bytes());
    hasher.update(source.as_bytes());
    hasher.update(&(keywords.len() as u64).to_le_bytes());
    for keyword in keywords {
        hasher.update(&(keyword.len() as u64).to_le_bytes());
        hasher.update(keyword.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn detector_digest(entries: &[PatternCoverageEvidence]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"keyhog.phase2-gpu-dfa.detectors.v1\0");
    hasher.update(&(entries.len() as u64).to_le_bytes());
    for entry in entries {
        hasher.update(&entry.phase2_index.to_le_bytes());
        hasher.update(&entry.pattern_digest);
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn validate_complete_evidence(
    entries: &[PatternCoverageEvidence],
    shards: &[Vec<u32>],
) -> Result<(), String> {
    let mut membership = Vec::new();
    membership
        .try_reserve(entries.len())
        .map_err(|error| format!("phase-2 GPU coverage membership reserve failed: {error}"))?;
    membership.resize(entries.len(), None);

    for (shard_index, shard) in shards.iter().enumerate() {
        if shard.is_empty() {
            return Err(format!("phase-2 GPU catalog shard {shard_index} is empty"));
        }
        let shard_index = u32::try_from(shard_index)
            .map_err(|error| format!("phase-2 GPU shard index exceeds artifact ABI: {error}"))?;
        for &phase2_index in shard {
            let entry = entries.get(phase2_index as usize).ok_or_else(|| {
                format!(
                    "phase-2 GPU shard {shard_index} contains out-of-range pattern {phase2_index}"
                )
            })?;
            let owner = &mut membership[phase2_index as usize];
            if let Some(prior) = owner.replace(shard_index) {
                return Err(format!(
                    "duplicate phase-2 GPU pattern {phase2_index} appears in shards {prior} and {shard_index}"
                ));
            }
            if entry.disposition != (PatternCoverageDisposition::GpuCovered { shard: shard_index })
            {
                return Err(format!(
                    "phase-2 GPU shard {shard_index} disagrees with coverage for pattern {phase2_index}"
                ));
            }
        }
    }

    for (expected, entry) in entries.iter().enumerate() {
        if entry.phase2_index as usize != expected {
            return Err(format!(
                "partial phase-2 GPU coverage evidence: entry {expected} records phase-2 index {}",
                entry.phase2_index
            ));
        }
        match entry.disposition {
            PatternCoverageDisposition::GpuCovered { shard }
                if membership[expected] != Some(shard) =>
            {
                return Err(format!(
                    "phase-2 GPU coverage for pattern {} is absent from shard {shard}",
                    entry.phase2_index
                ));
            }
            PatternCoverageDisposition::CpuRequired(_) if membership[expected].is_some() => {
                return Err(format!(
                    "CPU-required phase-2 pattern {} appears in a GPU shard",
                    entry.phase2_index
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn digest_payload(
    detector_digest: [u8; 32],
    entries: &[PatternCoverageEvidence],
    shards: &[Vec<u32>],
) -> Result<[u8; 32], String> {
    let payload = serde_json::to_vec(&(
        PHASE2_GPU_DFA_ARTIFACT_VERSION,
        detector_digest,
        entries,
        shards,
    ))
    .map_err(|error| format!("phase-2 GPU catalog digest serialization failed: {error}"))?;
    Ok(*blake3::hash(&payload).as_bytes())
}
