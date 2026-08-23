//! GPU regex-DFA admission for prefixless always-active phase-2 patterns.
//!
//! This is deliberately an admission accelerator, not a replacement for the
//! phase-2 extractor. A GPU hit only says "this chunk must run the shared
//! phase-2 tail"; extraction still uses the existing CPU regex path so recall,
//! confidence, suppression, and reporting stay under one owner. A GPU miss is
//! trusted only as "no covered prefixless pattern was seen"; uncovered patterns
//! and dispatch failures continue through the CPU admission gate.
//!
//! Coverage is deliberately narrow. Compiler-generated homoglyph variants are
//! excluded because phase one already admits their base detector on a row with
//! no confusable glyph, which is the same invariant `homoglyph_ascii_skip`
//! relies on. They cannot be added: a single homoglyph variant needs more than
//! 1024 NFA states and vyre's GPU regex pipeline caps a pipeline at
//! `LANES * 32 == 1024` by construction, so the pool does not lower at all.

#[cfg(test)]
use self::batch::ZeroPhase2GpuDfaScratch;
use self::batch::{
    build_packed_region_batch, build_packed_region_batch_refs, with_phase2_gpu_dfa_scratch,
    Phase2GpuDfaScratch,
};
use self::candidates::{
    ascii_phase2_gpu_dfa_candidates, cpu_required_reason, prefixless_always_active_candidates,
};
#[cfg(test)]
use self::lowering::regex_dfa_source_for_pattern;
use self::lowering::{
    build_shard, build_shards_recursive, detector_digest, pattern_digest, validate_catalog_limits,
    validate_complete_evidence, CpuRequiredReason, PatternCoverageDisposition,
    PatternCoverageEvidence, Phase2GpuDfaArtifact,
};
pub(super) use self::shard::match_region;
use self::shard::Phase2GpuDfaShard;
#[cfg(test)]
pub(super) use self::workload::build_phase2_gpu_admission_workload;
pub(super) use self::workload::Phase2GpuAdmissionWorkload;
pub(crate) use self::workload::Phase2GpuDfaAdmission;
pub(super) use self::workload::{
    build_phase2_gpu_admission_workload_filtered, expand_phase2_gpu_admission,
    validate_phase2_gpu_trigger_rows,
};
use super::*;
use std::sync::OnceLock;

/// The compiled artifact class for Phase-2 GPU DFA catalogs.
#[allow(dead_code)]
pub(crate) const ARTIFACT_CLASS: keyhog_core::CompiledArtifactClass =
    keyhog_core::CompiledArtifactClass::Phase2GpuDfaCatalog;

mod batch;
mod candidates;
mod lowering;
mod resident;
mod shard;
mod workload;

const PHASE2_GPU_DFA_MAX_STATES: usize = 16_384;

fn report_phase2_gpu_catalog_loss(reason: impl std::fmt::Display) {
    let reason = reason.to_string();
    static PHASE2_GPU_CATALOG_LOSS_WARNED: OnceLock<()> = OnceLock::new();
    if PHASE2_GPU_CATALOG_LOSS_WARNED.set(()).is_ok() {
        eprintln!(
            "keyhog: phase-2 GPU regex-DFA catalog incomplete ({reason}); CPU admission remains \
             authoritative for uncovered patterns. GPU speed evidence is incomplete."
        );
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase2GpuDfaProgramKind {
    CudaCompatible,
    SubgroupCoalesced,
}

impl Phase2GpuDfaProgramKind {
    fn for_backend_id(backend_id: Option<&str>) -> Self {
        if backend_id == Some("cuda") {
            Self::CudaCompatible
        } else {
            Self::SubgroupCoalesced
        }
    }

    const fn use_subgroup_coalesce(self) -> bool {
        matches!(self, Self::SubgroupCoalesced)
    }
}

#[derive(Debug)]
pub(crate) struct Phase2GpuDfaCatalog {
    shards: Vec<Phase2GpuDfaShard>,
    uncovered_ascii_patterns: usize,
    excluded_ascii_redundant_patterns: usize,
    evidence: Vec<PatternCoverageEvidence>,
    detector_digest: [u8; 32],
    catalog_digest: [u8; 32],
    resident: resident::Phase2GpuDfaCatalogResident,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Phase2GpuDfaCoverage {
    pub(crate) total_patterns: usize,
    pub(crate) covered_ascii_patterns: usize,
    pub(crate) cpu_required_patterns: usize,
    pub(crate) uncovered_ascii_patterns: usize,
    pub(crate) excluded_ascii_redundant_patterns: usize,
    pub(crate) shards: usize,
    pub(crate) catalog_digest: [u8; 32],
}

#[derive(Debug, Default)]
pub(crate) struct Phase2GpuDfaCatalogCache {
    catalog: OnceLock<Option<Phase2GpuDfaCatalog>>,
    preparation_ns: std::sync::atomic::AtomicU64,
}

impl Phase2GpuDfaCatalog {
    #[inline]
    pub(crate) fn has_shards(&self) -> bool {
        !self.shards.is_empty()
    }

    pub(crate) fn coverage(&self) -> Phase2GpuDfaCoverage {
        let covered_ascii_patterns = self
            .evidence
            .iter()
            .filter(|entry| {
                matches!(
                    entry.disposition,
                    PatternCoverageDisposition::GpuCovered { .. }
                )
            })
            .count();
        Phase2GpuDfaCoverage {
            total_patterns: self.evidence.len(),
            covered_ascii_patterns,
            cpu_required_patterns: self.evidence.len().saturating_sub(covered_ascii_patterns),
            uncovered_ascii_patterns: self.uncovered_ascii_patterns,
            excluded_ascii_redundant_patterns: self.excluded_ascii_redundant_patterns,
            shards: self.shards.len(),
            catalog_digest: self.catalog_digest,
        }
    }

    fn coverage_artifact(&self) -> Result<Phase2GpuDfaArtifact, String> {
        let artifact = Phase2GpuDfaArtifact::build(
            self.detector_digest,
            self.evidence.clone(),
            self.shards
                .iter()
                .map(|shard| {
                    shard
                        .phase2_indices
                        .iter()
                        .map(|&index| u32::try_from(index).map_err(|error| error.to_string()))
                        .collect()
                })
                .collect::<Result<Vec<Vec<u32>>, String>>()?,
        )?;
        if artifact.catalog_digest() != self.catalog_digest {
            return Err("phase-2 GPU catalog digest changed after construction".to_string());
        }
        Ok(artifact)
    }

    #[cfg(test)]
    fn coverage_artifact_bytes_for_test(&self) -> Result<Vec<u8>, String> {
        self.coverage_artifact()?.encode()
    }

    #[cfg(test)]
    fn validate_coverage_artifact_for_test(&self, bytes: &[u8]) -> Result<(), String> {
        let artifact = Phase2GpuDfaArtifact::decode(bytes, self.detector_digest)?;
        if artifact.catalog_digest() != self.catalog_digest || artifact.entries != self.evidence {
            return Err(
                "phase-2 GPU catalog artifact does not match the resident catalog".to_string(),
            );
        }
        Ok(())
    }

    /// The covered set a GPU miss is trusted for.
    ///
    /// The CPU prefilter marks every always-active pattern that matches, minus
    /// the compiler-generated homoglyph variants it skips on a row with no
    /// confusable glyph. A miss may only prove absence when every one of the
    /// remainder is in a shard, so anything the candidate filter drops for a
    /// reason OTHER than that proven redundancy (a gate-prefixed always-active
    /// pattern, a lowering failure) counts as uncovered.
    fn build(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        always_active_indices: &[usize],
        program_kind: Phase2GpuDfaProgramKind,
    ) -> Option<Self> {
        let all_candidates =
            prefixless_always_active_candidates(phase2_patterns, always_active_indices);
        let candidates = ascii_phase2_gpu_dfa_candidates(phase2_patterns, &all_candidates);
        let redundant = always_active_indices
            .iter()
            .filter(|&&idx| phase2_patterns[idx].0.homoglyph_variant)
            .count();
        let mut catalog = Self::build_from_selected_candidates(
            phase2_patterns,
            candidates.len(),
            redundant,
            &candidates,
            program_kind,
        )?;
        if let Err(error) = catalog.rebuild_evidence(phase2_patterns, |index, pattern, keywords| {
            cpu_required_reason(
                pattern,
                keywords,
                always_active_indices.binary_search(&index).is_ok(),
            )
        }) {
            report_phase2_gpu_catalog_loss(error);
            return None;
        }
        Some(catalog)
    }

    /// `required_pattern_count` is what the CPU prefilter would mark on a row
    /// of this scope's byte class; `candidates` is what lowering was attempted
    /// for. Anything the difference leaves out, plus every lowering failure,
    /// is uncovered, and an uncovered catalog is refused outright.
    fn build_from_selected_candidates(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        required_pattern_count: usize,
        excluded_ascii_redundant_patterns: usize,
        candidates: &[usize],
        program_kind: Phase2GpuDfaProgramKind,
    ) -> Option<Self> {
        if candidates.is_empty() {
            let mut catalog = (required_pattern_count == 0).then_some(Self {
                shards: Vec::new(),
                uncovered_ascii_patterns: 0,
                excluded_ascii_redundant_patterns,
                evidence: Vec::new(),
                detector_digest: [0; 32],
                catalog_digest: [0; 32],
                resident: resident::Phase2GpuDfaCatalogResident::default(),
            })?;
            catalog
                .rebuild_evidence(phase2_patterns, |_, pattern, _| {
                    Some(if pattern.homoglyph_variant {
                        CpuRequiredReason::AsciiHomoglyphRedundant
                    } else {
                        CpuRequiredReason::LoweringUnsupported
                    })
                })
                .ok()?;
            return Some(catalog);
        }

        let mut shards = Vec::new();
        let mut uncovered_ascii_patterns = required_pattern_count.saturating_sub(candidates.len());
        build_shards_recursive(
            phase2_patterns,
            candidates,
            program_kind.use_subgroup_coalesce(),
            &mut shards,
            &mut uncovered_ascii_patterns,
        );
        if let Err(error) = validate_catalog_limits(&shards) {
            report_phase2_gpu_catalog_loss(error);
            return None;
        }
        let covered_patterns: usize = shards.iter().map(|shard| shard.phase2_indices.len()).sum();
        // An incomplete catalog cannot prove absence, and a hit only tells the
        // CPU to do what it was already going to do, so every dispatch it
        // makes is pure cost. Refuse it and leave CPU admission authoritative.
        if shards.is_empty() || uncovered_ascii_patterns > 0 {
            tracing::warn!(
                target: "keyhog::gpu",
                required = required_pattern_count,
                covered = covered_patterns,
                uncovered = uncovered_ascii_patterns,
                shards = shards.len(),
                "phase-2 GPU regex-DFA admission cannot cover every prefixless always-active pattern for this scope; CPU admission remains authoritative"
            );
            report_phase2_gpu_catalog_loss(format!(
                "{uncovered_ascii_patterns} of {required_pattern_count} prefixless always-active pattern(s) did not lower to a GPU regex-DFA"
            ));
            return None;
        }
        tracing::debug!(
            target: "keyhog::gpu",
            shards = shards.len(),
            covered = covered_patterns,
            uncovered_ascii = uncovered_ascii_patterns,
            excluded_ascii_redundant = excluded_ascii_redundant_patterns,
            program = "region-admission",
            "phase-2 GPU regex-DFA ASCII admission catalog built"
        );
        let mut catalog = Self {
            shards,
            uncovered_ascii_patterns,
            excluded_ascii_redundant_patterns,
            evidence: Vec::new(),
            detector_digest: [0; 32],
            catalog_digest: [0; 32],
            resident: resident::Phase2GpuDfaCatalogResident::default(),
        };
        catalog
            .rebuild_evidence(phase2_patterns, |_, pattern, _| {
                Some(if pattern.homoglyph_variant {
                    CpuRequiredReason::AsciiHomoglyphRedundant
                } else {
                    CpuRequiredReason::LoweringUnsupported
                })
            })
            .ok()?;
        Some(catalog)
    }

    fn rebuild_evidence(
        &mut self,
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        cpu_reason: impl Fn(usize, &CompiledPattern, &[String]) -> Option<CpuRequiredReason>,
    ) -> Result<(), String> {
        let mut shard_for_pattern = vec![None; phase2_patterns.len()];
        for (shard_index, shard) in self.shards.iter().enumerate() {
            let shard_index = u32::try_from(shard_index).map_err(|error| {
                format!("phase-2 GPU shard index exceeds artifact ABI: {error}")
            })?;
            for &phase2_index in &shard.phase2_indices {
                let slot = shard_for_pattern.get_mut(phase2_index).ok_or_else(|| {
                    format!("phase-2 GPU shard contains out-of-range pattern {phase2_index}")
                })?;
                if slot.replace(shard_index).is_some() {
                    return Err(format!(
                        "phase-2 GPU pattern {phase2_index} appears in more than one shard"
                    ));
                }
            }
        }

        let mut evidence = Vec::new();
        evidence
            .try_reserve(phase2_patterns.len())
            .map_err(|error| format!("phase-2 GPU coverage evidence reserve failed: {error}"))?;
        for (index, (pattern, keywords)) in phase2_patterns.iter().enumerate() {
            let phase2_index = u32::try_from(index).map_err(|error| {
                format!("phase-2 GPU pattern index exceeds artifact ABI: {error}")
            })?;
            let disposition = match shard_for_pattern[index] {
                Some(shard) => PatternCoverageDisposition::GpuCovered { shard },
                None => PatternCoverageDisposition::CpuRequired(
                    cpu_reason(index, pattern, keywords).ok_or_else(|| {
                        format!(
                            "phase-2 pattern {index} has no GPU shard and no explicit CPU-required classification"
                        )
                    })?,
                ),
            };
            evidence.push(PatternCoverageEvidence {
                phase2_index,
                pattern_digest: pattern_digest(pattern, keywords),
                disposition,
            });
        }
        let detector_digest = detector_digest(&evidence);
        let shard_indices = self
            .shards
            .iter()
            .map(|shard| {
                shard
                    .phase2_indices
                    .iter()
                    .map(|&index| {
                        u32::try_from(index).map_err(|error| {
                            format!("phase-2 GPU pattern index exceeds artifact ABI: {error}")
                        })
                    })
                    .collect::<Result<Vec<u32>, String>>()
            })
            .collect::<Result<Vec<Vec<u32>>, String>>()?;
        let artifact =
            Phase2GpuDfaArtifact::build(detector_digest, evidence.clone(), shard_indices)?;
        validate_complete_evidence(&evidence, &artifact.shards)?;
        self.evidence = evidence;
        self.detector_digest = detector_digest;
        self.catalog_digest = artifact.catalog_digest();
        Ok(())
    }

    #[cfg(test)]
    fn single_shard_catalogs_for_test(&self) -> Vec<Self> {
        self.shards
            .iter()
            .cloned()
            .filter_map(|shard| {
                let mut catalog = Self {
                    shards: vec![shard],
                    uncovered_ascii_patterns: self.uncovered_ascii_patterns,
                    excluded_ascii_redundant_patterns: self.excluded_ascii_redundant_patterns,
                    evidence: Vec::new(),
                    detector_digest: [0; 32],
                    catalog_digest: [0; 32],
                    resident: resident::Phase2GpuDfaCatalogResident::default(),
                };
                let patterns = self
                    .evidence
                    .iter()
                    .map(|entry| entry.pattern_digest)
                    .collect::<Vec<_>>();
                let shard_indices = catalog.shards[0].phase2_indices.clone();
                catalog.evidence = self.evidence.clone();
                for entry in &mut catalog.evidence {
                    entry.disposition = if shard_indices.contains(&(entry.phase2_index as usize)) {
                        PatternCoverageDisposition::GpuCovered { shard: 0 }
                    } else {
                        PatternCoverageDisposition::CpuRequired(
                            CpuRequiredReason::LoweringUnsupported,
                        )
                    };
                }
                catalog.detector_digest = detector_digest(&catalog.evidence);
                let artifact = Phase2GpuDfaArtifact::build(
                    catalog.detector_digest,
                    catalog.evidence.clone(),
                    vec![shard_indices
                        .iter()
                        .map(|&index| u32::try_from(index).ok())
                        .collect::<Option<Vec<_>>>()?],
                )
                .ok()?;
                catalog.catalog_digest = artifact.catalog_digest();
                debug_assert_eq!(patterns.len(), catalog.evidence.len());
                Some(catalog)
            })
            .collect()
    }

    pub(crate) fn scan_admission_refs(
        &self,
        backend: &std::sync::Arc<dyn vyre::VyreBackend>,
        chunks: &[&keyhog_core::Chunk],
    ) -> std::result::Result<Phase2GpuDfaAdmission, String> {
        self.scan_admission_with_builder(backend, chunks.len(), |scratch| {
            build_packed_region_batch_refs(chunks, scratch)
        })
    }

    pub(crate) fn scan_admission_chunks(
        &self,
        backend: &std::sync::Arc<dyn vyre::VyreBackend>,
        chunks: &[keyhog_core::Chunk],
    ) -> std::result::Result<Phase2GpuDfaAdmission, String> {
        self.scan_admission_with_builder(backend, chunks.len(), |scratch| {
            build_packed_region_batch(chunks, scratch)
        })
    }

    fn scan_admission_with_builder<F>(
        &self,
        backend: &std::sync::Arc<dyn vyre::VyreBackend>,
        chunk_count: usize,
        build_batch: F,
    ) -> std::result::Result<Phase2GpuDfaAdmission, String>
    where
        F: FnOnce(&mut Phase2GpuDfaScratch) -> std::result::Result<(), String>,
    {
        if chunk_count == 0 || self.shards.is_empty() {
            return Ok(Phase2GpuDfaAdmission {
                admitted: vec![false; chunk_count],
                complete: vec![true; chunk_count],
                matches_seen: 0,
                candidate_bits: Vec::new(),
                candidate_words_per_region: 0,
                candidate_phase2_indices: Vec::new(),
            });
        }
        with_phase2_gpu_dfa_scratch(|scratch| {
            build_batch(scratch)?;
            self.scan_admission_with_scratch(backend, scratch, chunk_count)
        })
    }

    fn scan_admission_with_scratch(
        &self,
        backend: &std::sync::Arc<dyn vyre::VyreBackend>,
        scratch: &mut Phase2GpuDfaScratch,
        chunk_count: usize,
    ) -> std::result::Result<Phase2GpuDfaAdmission, String> {
        use vyre::scan::dispatch_io;

        let haystack_len = u32::try_from(scratch.haystack_len).map_err(|error| {
            format!(
                "phase2_gpu_regex_dfa haystack is {} byte(s), above the u32 GPU ABI: {error}",
                scratch.haystack_len
            )
        })?;
        if haystack_len > dispatch_io::DEFAULT_MAX_SCAN_BYTES {
            return Err(format!(
                "phase2_gpu_regex_dfa scan-guard ceiling exceeded: {} byte(s) > {} byte(s). Fix: split the scan before dispatch.",
                haystack_len,
                dispatch_io::DEFAULT_MAX_SCAN_BYTES
            ));
        }

        let mut admitted = vec![false; chunk_count];
        let complete = vec![self.uncovered_ascii_patterns == 0; chunk_count];
        let candidate_words_per_region = self.shards.iter().try_fold(0usize, |total, shard| {
            let pattern_count = u32::try_from(shard.phase2_indices.len()).map_err(|error| {
                format!("phase-2 GPU candidate count exceeds the u32 ABI: {error}")
            })?;
            total
                .checked_add(
                    vyre_libs::scan::regex_admission_presence_words(pattern_count) as usize,
                )
                .ok_or_else(|| "phase-2 GPU candidate-word count overflow".to_string())
        })?;
        let candidate_word_count = candidate_words_per_region
            .checked_mul(chunk_count)
            .ok_or_else(|| "phase-2 GPU candidate output size overflow".to_string())?;
        let candidate_bytes = candidate_word_count
            .checked_mul(std::mem::size_of::<u32>())
            .ok_or_else(|| "phase-2 GPU candidate output byte size overflow".to_string())?;
        if candidate_bytes > dispatch_io::DEFAULT_MAX_SCAN_BYTES as usize {
            return Err(format!(
                "phase-2 GPU candidate output ceiling exceeded: {candidate_bytes} > {}",
                dispatch_io::DEFAULT_MAX_SCAN_BYTES
            ));
        }
        let mut candidate_bits = Vec::new();
        candidate_bits
            .try_reserve(candidate_word_count)
            .map_err(|error| format!("phase-2 GPU candidate output reserve failed: {error}"))?;
        candidate_bits.resize(candidate_word_count, 0);
        let candidate_map_len = candidate_words_per_region
            .checked_mul(u32::BITS as usize)
            .ok_or_else(|| "phase-2 GPU candidate map size overflow".to_string())?;
        let mut candidate_phase2_indices = Vec::new();
        candidate_phase2_indices
            .try_reserve(candidate_map_len)
            .map_err(|error| format!("phase-2 GPU candidate map reserve failed: {error}"))?;
        for shard in &self.shards {
            for &phase2_index in &shard.phase2_indices {
                candidate_phase2_indices.push(u32::try_from(phase2_index).map_err(|error| {
                    format!("phase-2 GPU candidate phase-2 index exceeds ABI: {error}")
                })?);
            }
            let shard_words = vyre_libs::scan::regex_admission_presence_words(
                u32::try_from(shard.phase2_indices.len())
                    .map_err(|error| format!("phase-2 GPU candidate count exceeds ABI: {error}"))?,
            ) as usize;
            let padding = shard_words
                .checked_mul(u32::BITS as usize)
                .and_then(|slots| slots.checked_sub(shard.phase2_indices.len()))
                .ok_or_else(|| "phase-2 GPU shard candidate map overflow".to_string())?;
            let shard_map_end = candidate_phase2_indices
                .len()
                .checked_add(padding)
                .ok_or_else(|| "phase-2 GPU candidate map offset overflow".to_string())?;
            candidate_phase2_indices.resize(shard_map_end, u32::MAX);
        }
        if candidate_phase2_indices.len() != candidate_map_len {
            return Err("phase-2 GPU candidate map layout changed after sizing".to_string());
        }
        let evidence_seen = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.resident.scan(
                &self.shards,
                backend,
                scratch,
                haystack_len,
                &mut admitted,
                &mut candidate_bits,
                candidate_words_per_region,
            )
        }))
        .map_err(|panic| {
            format!(
                "phase-2 GPU resident admission panicked: {}. Fix: repair the selected GPU driver/runtime and recalibrate autoroute",
                crate::error::panic_payload_detail(panic)
            )
        })??;
        Ok(Phase2GpuDfaAdmission {
            admitted,
            complete,
            matches_seen: evidence_seen,
            candidate_bits,
            candidate_words_per_region,
            candidate_phase2_indices,
        })
    }

    fn build_from_artifact(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        always_active_indices: &[usize],
        program_kind: Phase2GpuDfaProgramKind,
        bytes: &[u8],
    ) -> Result<Self, String> {
        let mut expected_entries = Vec::new();
        expected_entries
            .try_reserve(phase2_patterns.len())
            .map_err(|error| format!("phase-2 GPU artifact evidence reserve failed: {error}"))?;
        for (index, (pattern, keywords)) in phase2_patterns.iter().enumerate() {
            expected_entries.push(PatternCoverageEvidence {
                phase2_index: u32::try_from(index)
                    .map_err(|error| format!("phase-2 GPU pattern index exceeds ABI: {error}"))?,
                pattern_digest: pattern_digest(pattern, keywords),
                disposition: PatternCoverageDisposition::CpuRequired(
                    CpuRequiredReason::LoweringUnsupported,
                ),
            });
        }
        let expected_detector_digest = detector_digest(&expected_entries);
        let artifact = Phase2GpuDfaArtifact::decode(bytes, expected_detector_digest)?;
        if artifact.entries.len() != phase2_patterns.len() {
            return Err(format!(
                "partial phase-2 GPU artifact evidence: {} entries for {} production patterns",
                artifact.entries.len(),
                phase2_patterns.len()
            ));
        }
        for (index, ((pattern, keywords), entry)) in
            phase2_patterns.iter().zip(&artifact.entries).enumerate()
        {
            if entry.pattern_digest != pattern_digest(pattern, keywords) {
                return Err(format!(
                    "phase-2 GPU artifact pattern digest mismatch at production index {index}"
                ));
            }
            let expected_cpu_reason = cpu_required_reason(
                pattern,
                keywords,
                always_active_indices.binary_search(&index).is_ok(),
            );
            match (expected_cpu_reason, entry.disposition) {
                (None, PatternCoverageDisposition::GpuCovered { .. }) => {}
                (Some(expected), PatternCoverageDisposition::CpuRequired(actual))
                    if expected == actual => {}
                (None, PatternCoverageDisposition::CpuRequired(_)) => {
                    return Err(format!(
                        "phase-2 pattern {index} has no persisted GPU coverage decision; rebuild the execution pack"
                    ));
                }
                (Some(expected), actual) => {
                    return Err(format!(
                        "phase-2 pattern {index} coverage decision is {actual:?}, expected CpuRequired({expected:?})"
                    ));
                }
            }
        }

        let mut shards = Vec::new();
        shards
            .try_reserve(artifact.shards.len())
            .map_err(|error| format!("phase-2 GPU artifact shard reserve failed: {error}"))?;
        for artifact_shard in &artifact.shards {
            let mut indices = Vec::new();
            indices.try_reserve(artifact_shard.len()).map_err(|error| {
                format!("phase-2 GPU artifact shard-index reserve failed: {error}")
            })?;
            indices.extend(artifact_shard.iter().map(|&index| index as usize));
            shards.push(build_shard(
                phase2_patterns,
                &indices,
                program_kind.use_subgroup_coalesce(),
            )?);
        }
        validate_catalog_limits(&shards)?;
        let excluded_ascii_redundant_patterns = artifact
            .entries
            .iter()
            .filter(|entry| {
                entry.disposition
                    == PatternCoverageDisposition::CpuRequired(
                        CpuRequiredReason::AsciiHomoglyphRedundant,
                    )
            })
            .count();
        let catalog_digest = artifact.catalog_digest();
        Ok(Self {
            shards,
            uncovered_ascii_patterns: 0,
            excluded_ascii_redundant_patterns,
            evidence: artifact.entries,
            detector_digest: expected_detector_digest,
            catalog_digest,
            resident: resident::Phase2GpuDfaCatalogResident::default(),
        })
    }
}

impl Phase2GpuDfaCatalogCache {
    pub(crate) fn from_artifact(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        always_active_indices: &[usize],
        backend_id: Option<&'static str>,
        bytes: &[u8],
    ) -> Result<Self, String> {
        let started = std::time::Instant::now();
        let catalog = Phase2GpuDfaCatalog::build_from_artifact(
            phase2_patterns,
            always_active_indices,
            Phase2GpuDfaProgramKind::for_backend_id(backend_id),
            bytes,
        )?;
        let elapsed_ns = (started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64).max(1);
        let slot = OnceLock::new();
        slot.set(Some(catalog))
            .map_err(|_| "phase-2 GPU artifact cache was initialized twice".to_string())?;
        Ok(Self {
            catalog: slot,
            preparation_ns: std::sync::atomic::AtomicU64::new(elapsed_ns),
        })
    }

    pub(crate) fn catalog(
        &self,
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        always_active_indices: &[usize],
        backend_id: Option<&'static str>,
    ) -> Option<&Phase2GpuDfaCatalog> {
        self.catalog
            .get_or_init(|| {
                let started = std::time::Instant::now();
                let catalog = Phase2GpuDfaCatalog::build(
                    phase2_patterns,
                    always_active_indices,
                    Phase2GpuDfaProgramKind::for_backend_id(backend_id),
                );
                let elapsed_ns =
                    (started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64).max(1);
                self.preparation_ns
                    .store(elapsed_ns, std::sync::atomic::Ordering::Release);
                catalog
            })
            .as_ref()
    }

    pub(crate) fn preparation_ns(&self, _backend_id: Option<&'static str>) -> u128 {
        self.preparation_ns
            .load(std::sync::atomic::Ordering::Acquire) as u128
    }
}

pub(crate) fn compile_phase2_gpu_catalog_artifact(
    detectors: &[keyhog_core::DetectorSpec],
    backend_id: Option<&'static str>,
) -> Result<Vec<u8>, String> {
    let state = crate::compiler::build_compile_state(detectors)
        .map_err(|error| format!("phase-2 GPU catalog compile state failed: {error}"))?;
    crate::compiler::validate_compiled_pattern_detector_indices(
        &state.ac_map,
        &state.phase2_patterns,
        detectors.len(),
    )
    .map_err(|error| format!("phase-2 GPU catalog pattern validation failed: {error}"))?;
    let always_active_indices =
        crate::compiler::phase2_always_active_indices(&state.phase2_patterns);
    let catalog = Phase2GpuDfaCatalog::build(
        &state.phase2_patterns,
        &always_active_indices,
        Phase2GpuDfaProgramKind::for_backend_id(backend_id),
    )
    .ok_or_else(|| {
        "phase-2 GPU catalog is incomplete; every new compatible registry pattern requires an explicit GPU or CPU coverage decision"
            .to_string()
    })?;
    catalog.coverage_artifact()?.encode()
}

#[cfg(test)]
#[path = "../../tests/unit/engine_phase2_gpu_dfa.rs"]
mod tests;
