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
use self::candidates::{
    prefixless_always_active_candidates, prioritized_phase2_gpu_dfa_candidates,
};
use self::lowering::build_shards_recursive;
#[cfg(test)]
use self::lowering::regex_dfa_source_for_pattern;
#[cfg(test)]
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
mod shard;
mod workload;

const PHASE2_GPU_DFA_MAX_MATCHES: u32 = 1 << 20;
const PHASE2_GPU_DFA_MAX_STATES: usize = 16_384;
const PHASE2_GPU_DFA_TARGET_SHARD_PATTERNS: usize = 16;
// Normal scans build this catalog lazily; autoroute calibration prepares it and
// accounts for that cold cost explicitly. Keep breadth bounded by shard count;
// selection quality comes from detector-breadth ordering, not from letting
// first-use regex-DFA compilation consume the operator's scan.
const PHASE2_GPU_DFA_MAX_SHARDS: usize = 4;
const PHASE2_GPU_DFA_MAX_CANDIDATES: usize =
    PHASE2_GPU_DFA_TARGET_SHARD_PATTERNS * PHASE2_GPU_DFA_MAX_SHARDS;

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
    uncovered_patterns: usize,
}

#[derive(Debug, Default)]
pub(crate) struct Phase2GpuDfaCatalogCache {
    subgroup: OnceLock<Option<Phase2GpuDfaCatalog>>,
    cuda: OnceLock<Option<Phase2GpuDfaCatalog>>,
    subgroup_preparation_ns: std::sync::atomic::AtomicU64,
    cuda_preparation_ns: std::sync::atomic::AtomicU64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase2GpuDfaProgramKind {
    SubgroupCoalesced,
    CudaCompatible,
}

impl Phase2GpuDfaProgramKind {
    fn for_backend_id(backend_id: Option<&'static str>) -> Self {
        match backend_id {
            Some("cuda") => Self::CudaCompatible,
            _ => Self::SubgroupCoalesced,
        }
    }

    fn use_subgroup_coalesce(self) -> bool {
        matches!(self, Self::SubgroupCoalesced)
    }

    fn label(self) -> &'static str {
        match self {
            Self::SubgroupCoalesced => "subgroup-coalesced",
            Self::CudaCompatible => "cuda-compatible",
        }
    }
}

impl Phase2GpuDfaCatalog {
    fn build(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        always_active_indices: &[usize],
        program_kind: Phase2GpuDfaProgramKind,
    ) -> Option<Self> {
        let all_candidates =
            prefixless_always_active_candidates(phase2_patterns, always_active_indices);
        let candidates = prioritized_phase2_gpu_dfa_candidates(
            phase2_patterns,
            &all_candidates,
            PHASE2_GPU_DFA_MAX_CANDIDATES,
        );
        Self::build_from_selected_candidates(
            phase2_patterns,
            all_candidates.len(),
            &candidates,
            program_kind,
        )
    }

    fn build_from_selected_candidates(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        all_candidate_count: usize,
        candidates: &[usize],
        program_kind: Phase2GpuDfaProgramKind,
    ) -> Option<Self> {
        if candidates.is_empty() {
            return None;
        }

        let use_subgroup_coalesce = program_kind.use_subgroup_coalesce();
        let mut shards = Vec::new();
        let mut uncovered_patterns = all_candidate_count.saturating_sub(candidates.len());
        if uncovered_patterns > 0 {
            tracing::warn!(
                target: "keyhog::gpu",
                selected = candidates.len(),
                uncovered = uncovered_patterns,
                candidate_budget = PHASE2_GPU_DFA_MAX_CANDIDATES,
                "phase-2 GPU regex-DFA admission candidate budget reached; GPU hits can admit selected prefixless patterns, misses still consult CPU admission"
            );
            report_phase2_gpu_catalog_loss(format!(
                "candidate budget reached: selected {} of {} prefixless always-active pattern(s)",
                candidates.len(),
                all_candidate_count
            ));
        }
        for chunk in candidates.chunks(PHASE2_GPU_DFA_TARGET_SHARD_PATTERNS) {
            build_shards_recursive(
                phase2_patterns,
                chunk,
                use_subgroup_coalesce,
                &mut shards,
                &mut uncovered_patterns,
            );
        }
        let covered_patterns: usize = shards.iter().map(|shard| shard.phase2_indices.len()).sum();
        if shards.is_empty() {
            tracing::warn!(
                target: "keyhog::gpu",
                candidates = all_candidate_count,
                "phase-2 GPU regex-DFA admission has no lowerable prefixless always-active pattern; CPU admission remains authoritative"
            );
            report_phase2_gpu_catalog_loss(format!(
                "no lowerable prefixless always-active pattern among {all_candidate_count} candidate(s)"
            ));
            return None;
        }
        if uncovered_patterns > 0 {
            tracing::warn!(
                target: "keyhog::gpu",
                covered = covered_patterns,
                uncovered = uncovered_patterns,
                "phase-2 GPU regex-DFA admission has uncovered prefixless pattern(s); GPU hits can admit chunks, misses still consult CPU admission"
            );
            report_phase2_gpu_catalog_loss(format!(
                "{uncovered_patterns} prefixless always-active pattern(s) uncovered after lowering"
            ));
        }
        tracing::debug!(
            target: "keyhog::gpu",
            shards = shards.len(),
            covered = covered_patterns,
            uncovered = uncovered_patterns,
            program = program_kind.label(),
            "phase-2 GPU regex-DFA admission catalog built"
        );
        Some(Self {
            shards,
            uncovered_patterns,
        })
    }

    pub(crate) fn scan_admission_refs(
        &self,
        backend: &dyn vyre::VyreBackend,
        chunks: &[&keyhog_core::Chunk],
    ) -> std::result::Result<Phase2GpuDfaAdmission, String> {
        self.scan_admission_with_builder(backend, chunks.len(), |scratch| {
            build_packed_region_batch_refs(chunks, scratch)
        })
    }

    pub(crate) fn scan_admission_chunks(
        &self,
        backend: &dyn vyre::VyreBackend,
        chunks: &[keyhog_core::Chunk],
    ) -> std::result::Result<Phase2GpuDfaAdmission, String> {
        self.scan_admission_with_builder(backend, chunks.len(), |scratch| {
            build_packed_region_batch(chunks, scratch)
        })
    }

    fn scan_admission_with_builder<F>(
        &self,
        backend: &dyn vyre::VyreBackend,
        chunk_count: usize,
        build_batch: F,
    ) -> std::result::Result<Phase2GpuDfaAdmission, String>
    where
        F: FnOnce(&mut Phase2GpuDfaScratch) -> std::result::Result<(), String>,
    {
        if chunk_count == 0 || self.shards.is_empty() {
            return Ok(Phase2GpuDfaAdmission {
                admitted: vec![false; chunk_count],
                complete: true,
                matches_seen: 0,
                marked: vec![Vec::new(); chunk_count],
            });
        }
        with_phase2_gpu_dfa_scratch(|scratch| {
            build_batch(scratch)?;
            self.scan_admission_with_scratch(backend, scratch, chunk_count)
        })
    }

    fn scan_admission_with_scratch(
        &self,
        backend: &dyn vyre::VyreBackend,
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
        let mut complete = self.uncovered_patterns == 0;
        let mut matches_seen = 0usize;
        // Step-1 marking accumulator: per-region (== per-chunk in the coalesced
        // batch) phase-2 pattern indices the GPU regex-DFA matched, unioned across
        // shards. Only meaningful when `complete` (GPU covered every always-active
        // pattern) (then the caller can substitute this for the CPU RegexSet mark).
        let mut marked: Vec<Vec<usize>> = vec![Vec::new(); chunk_count];
        for shard in &self.shards {
            let shard_incomplete = shard.scan_admission_into(
                backend,
                scratch,
                haystack_len,
                &mut admitted,
                Some(&mut marked),
            )?;
            matches_seen = matches_seen.saturating_add(scratch.matches.len());
            if shard_incomplete {
                complete = false;
            }
        }
        // Dedup each region's marks (a pattern can match multiple times per region;
        // the active set is a membership set, mirroring `scratch.mark`'s idempotence).
        for region in &mut marked {
            region.sort_unstable();
            region.dedup();
        }
        Ok(Phase2GpuDfaAdmission {
            admitted,
            complete,
            matches_seen,
            marked,
        })
    }
}

impl Phase2GpuDfaCatalogCache {
    pub(crate) fn catalog(
        &self,
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        always_active_indices: &[usize],
        backend_id: Option<&'static str>,
    ) -> Option<&Phase2GpuDfaCatalog> {
        let program_kind = Phase2GpuDfaProgramKind::for_backend_id(backend_id);
        let cell = match program_kind {
            Phase2GpuDfaProgramKind::SubgroupCoalesced => &self.subgroup,
            Phase2GpuDfaProgramKind::CudaCompatible => &self.cuda,
        };
        let preparation_ns = match program_kind {
            Phase2GpuDfaProgramKind::SubgroupCoalesced => &self.subgroup_preparation_ns,
            Phase2GpuDfaProgramKind::CudaCompatible => &self.cuda_preparation_ns,
        };
        cell.get_or_init(|| {
            let started = std::time::Instant::now();
            let catalog =
                Phase2GpuDfaCatalog::build(phase2_patterns, always_active_indices, program_kind);
            let elapsed_ns = u64::try_from(started.elapsed().as_nanos())
                .unwrap_or(u64::MAX)
                .max(1);
            preparation_ns.store(elapsed_ns, std::sync::atomic::Ordering::Release);
            catalog
        })
        .as_ref()
    }

    pub(crate) fn preparation_ns(&self, backend_id: Option<&'static str>) -> u128 {
        let preparation_ns = match Phase2GpuDfaProgramKind::for_backend_id(backend_id) {
            Phase2GpuDfaProgramKind::SubgroupCoalesced => &self.subgroup_preparation_ns,
            Phase2GpuDfaProgramKind::CudaCompatible => &self.cuda_preparation_ns,
        };
        preparation_ns.load(std::sync::atomic::Ordering::Acquire) as u128
    }
}

#[cfg(test)]
#[path = "../../tests/unit/engine_phase2_gpu_dfa.rs"]
mod tests;
