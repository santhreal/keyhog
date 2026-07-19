//! GPU regex-DFA admission for prefixless always-active phase-2 patterns.
//!
//! This is deliberately an admission accelerator, not a replacement for the
//! phase-2 extractor. A GPU hit only says "this chunk must run the shared
//! phase-2 tail"; extraction still uses the existing CPU regex path so recall,
//! confidence, suppression, and reporting stay under one owner. A GPU miss is
//! trusted only as "no covered prefixless pattern was seen"; uncovered patterns
//! and dispatch failures continue through the CPU admission gate.

#[cfg(test)]
use self::batch::ZeroPhase2GpuDfaScratch;
use self::batch::{
    build_packed_region_batch, build_packed_region_batch_refs, with_phase2_gpu_dfa_scratch,
    Phase2GpuDfaScratch,
};
use self::candidates::{ascii_phase2_gpu_dfa_candidates, prefixless_always_active_candidates};
use self::lowering::build_shards_recursive;
#[cfg(test)]
use self::lowering::regex_dfa_source_for_pattern;
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

#[derive(Debug)]
pub(crate) struct Phase2GpuDfaCatalog {
    shards: Vec<Phase2GpuDfaShard>,
    uncovered_ascii_patterns: usize,
    excluded_ascii_redundant_patterns: usize,
    resident: resident::Phase2GpuDfaCatalogResident,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Phase2GpuDfaCoverage {
    pub(crate) covered_ascii_patterns: usize,
    pub(crate) uncovered_ascii_patterns: usize,
    pub(crate) excluded_ascii_redundant_patterns: usize,
    pub(crate) shards: usize,
}

#[derive(Debug, Default)]
pub(crate) struct Phase2GpuDfaCatalogCache {
    catalog: OnceLock<Option<Phase2GpuDfaCatalog>>,
    preparation_ns: std::sync::atomic::AtomicU64,
}

impl Phase2GpuDfaCatalog {
    pub(crate) fn coverage(&self) -> Phase2GpuDfaCoverage {
        Phase2GpuDfaCoverage {
            covered_ascii_patterns: self
                .shards
                .iter()
                .map(|shard| shard.phase2_indices.len())
                .sum(),
            uncovered_ascii_patterns: self.uncovered_ascii_patterns,
            excluded_ascii_redundant_patterns: self.excluded_ascii_redundant_patterns,
            shards: self.shards.len(),
        }
    }

    fn build(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        always_active_indices: &[usize],
    ) -> Option<Self> {
        let all_candidates =
            prefixless_always_active_candidates(phase2_patterns, always_active_indices);
        let candidates = ascii_phase2_gpu_dfa_candidates(phase2_patterns, &all_candidates);
        Self::build_from_selected_candidates(
            phase2_patterns,
            candidates.len(),
            all_candidates.len().saturating_sub(candidates.len()),
            &candidates,
        )
    }

    fn build_from_selected_candidates(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        ascii_candidate_count: usize,
        excluded_ascii_redundant_patterns: usize,
        candidates: &[usize],
    ) -> Option<Self> {
        if candidates.is_empty() {
            return (ascii_candidate_count == 0).then_some(Self {
                shards: Vec::new(),
                uncovered_ascii_patterns: 0,
                excluded_ascii_redundant_patterns,
                resident: resident::Phase2GpuDfaCatalogResident::default(),
            });
        }

        let mut shards = Vec::new();
        let mut uncovered_ascii_patterns = ascii_candidate_count.saturating_sub(candidates.len());
        build_shards_recursive(
            phase2_patterns,
            candidates,
            &mut shards,
            &mut uncovered_ascii_patterns,
        );
        let covered_patterns: usize = shards.iter().map(|shard| shard.phase2_indices.len()).sum();
        if shards.is_empty() {
            tracing::warn!(
                target: "keyhog::gpu",
                candidates = ascii_candidate_count,
                "phase-2 GPU regex-DFA admission has no lowerable ASCII prefixless always-active pattern; CPU admission remains authoritative"
            );
            report_phase2_gpu_catalog_loss(format!(
                "no lowerable ASCII prefixless always-active pattern among {ascii_candidate_count} candidate(s)"
            ));
            return None;
        }
        if uncovered_ascii_patterns > 0 {
            tracing::warn!(
                target: "keyhog::gpu",
                covered = covered_patterns,
                uncovered = uncovered_ascii_patterns,
                "phase-2 GPU regex-DFA admission has uncovered ASCII prefixless pattern(s); GPU hits can admit chunks, misses still consult CPU admission"
            );
            report_phase2_gpu_catalog_loss(format!(
                "{uncovered_ascii_patterns} ASCII prefixless always-active pattern(s) uncovered after lowering"
            ));
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
        Some(Self {
            shards,
            uncovered_ascii_patterns,
            excluded_ascii_redundant_patterns,
            resident: resident::Phase2GpuDfaCatalogResident::default(),
        })
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
        use vyre_libs::scan::dispatch_io;

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
        let evidence_seen =
            self.resident
                .scan(&self.shards, backend, scratch, haystack_len, &mut admitted)?;
        Ok(Phase2GpuDfaAdmission {
            admitted,
            complete,
            matches_seen: evidence_seen,
        })
    }
}

impl Phase2GpuDfaCatalogCache {
    pub(crate) fn catalog(
        &self,
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        always_active_indices: &[usize],
        _backend_id: Option<&'static str>,
    ) -> Option<&Phase2GpuDfaCatalog> {
        self.catalog
            .get_or_init(|| {
                let started = std::time::Instant::now();
                let catalog = Phase2GpuDfaCatalog::build(phase2_patterns, always_active_indices);
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

#[cfg(test)]
#[path = "../../tests/unit/engine_phase2_gpu_dfa.rs"]
mod tests;
