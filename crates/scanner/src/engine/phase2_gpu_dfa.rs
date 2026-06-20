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
#[cfg(test)]
use self::candidates::valid_phase2_gpu_dfa_candidates;
use self::candidates::{
    prefixless_always_active_candidates, prioritized_phase2_gpu_dfa_candidates,
};
use self::lowering::build_shards_recursive;
#[cfg(test)]
use self::lowering::regex_dfa_source_for_pattern;
#[cfg(test)]
use self::shard::match_region;
use self::shard::Phase2GpuDfaShard;
pub(super) use self::workload::Phase2GpuAdmissionWorkload;
pub(crate) use self::workload::Phase2GpuDfaAdmission;
pub(super) use self::workload::{
    build_phase2_gpu_admission_workload, expand_phase2_gpu_admission,
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
// This catalog is still lazy-built on the scan path. Keep breadth bounded by
// shard count here; selection quality comes from detector-breadth ordering, not
// from letting first-use regex-DFA compilation consume the operator's scan.
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
        for shard in &self.shards {
            let shard_incomplete =
                shard.scan_admission_into(backend, scratch, haystack_len, &mut admitted)?;
            matches_seen = matches_seen.saturating_add(scratch.matches.len());
            if shard_incomplete {
                complete = false;
            }
        }
        Ok(Phase2GpuDfaAdmission {
            admitted,
            complete,
            matches_seen,
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
        cell.get_or_init(|| {
            Phase2GpuDfaCatalog::build(phase2_patterns, always_active_indices, program_kind)
        })
        .as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pattern(src: &str, case_insensitive: bool) -> CompiledPattern {
        test_pattern_with_shape(src, case_insensitive, 0, false)
    }

    fn test_pattern_with_shape(
        src: &str,
        case_insensitive: bool,
        detector_index: usize,
        homoglyph_variant: bool,
    ) -> CompiledPattern {
        let regex = if case_insensitive {
            LazyRegex::detector(src)
        } else {
            LazyRegex::plain(src)
        };
        CompiledPattern {
            detector_index,
            regex,
            group: None,
            client_safe: false,
            match_proves_keyword_nearby: false,
            homoglyph_variant,
        }
    }

    fn replay_catalog_admission(
        catalog: &Phase2GpuDfaCatalog,
        chunks: &[keyhog_core::Chunk],
    ) -> Vec<bool> {
        let mut scratch = Phase2GpuDfaScratch::default();
        build_packed_region_batch(chunks, &mut scratch).expect("region batch");
        let mut admitted = vec![false; chunks.len()];
        for shard in &catalog.shards {
            replay_shard_admission(shard, &scratch, &mut admitted);
        }
        admitted
    }

    fn replay_shard_admission(
        shard: &Phase2GpuDfaShard,
        scratch: &Phase2GpuDfaScratch,
        admitted: &mut [bool],
    ) {
        let dfa = &shard.pipeline.dfa;
        let mut state = 0u32;
        for (pos, &byte) in scratch.haystack.iter().enumerate() {
            state = dfa.transitions[(state as usize) * 256 + byte as usize];
            let begin = dfa.output_offsets[state as usize] as usize;
            let end = dfa.output_offsets[state as usize + 1] as usize;
            for &pattern_id in &dfa.output_records[begin..end] {
                let pattern_len = match shard.pipeline.pattern_lengths.get(pattern_id as usize) {
                    Some(&value) => value,
                    None => {
                        panic!(
                            "replayed GPU DFA emitted pattern id {} outside pattern_lengths len {}",
                            pattern_id,
                            shard.pipeline.pattern_lengths.len()
                        )
                    }
                };
                let end_offset = (pos as u32).saturating_add(1);
                let start_offset = end_offset.saturating_sub(pattern_len);
                if let Some(region) = match_region(
                    &scratch.region_starts,
                    scratch.haystack.len(),
                    start_offset,
                    end_offset,
                ) {
                    if let Some(slot) = admitted.get_mut(region) {
                        *slot = true;
                    }
                }
            }
        }
    }

    #[test]
    fn packed_region_batch_preserves_case_separates_pads_and_clears() {
        let chunks = [
            keyhog_core::Chunk::from("GhP_TOKEN"),
            keyhog_core::Chunk::from("Zz9"),
        ];
        let mut scratch = Phase2GpuDfaScratch::default();
        {
            let guard = ZeroPhase2GpuDfaScratch::new(&mut scratch);
            build_packed_region_batch(&chunks, guard.scratch).expect("batch");
            assert_eq!(guard.scratch.haystack, b"GhP_TOKEN\0Zz9");
            assert_eq!(guard.scratch.haystack_len, b"GhP_TOKEN\0Zz9".len());
            assert_eq!(
                guard.scratch.dispatch.haystack_bytes,
                b"GhP_TOKEN\0Zz9\0\0\0".to_vec(),
                "production upload scratch must be u32-padded directly without a second pack step"
            );
            assert_eq!(guard.scratch.region_starts, &[0, 10]);
        }
        assert!(scratch.haystack.is_empty());
        assert_eq!(scratch.haystack_len, 0);
        assert!(scratch.region_starts.is_empty());
        assert!(scratch.dispatch.haystack_bytes.is_empty());
    }

    #[test]
    fn match_region_rejects_degenerate_and_cross_region_hits() {
        let starts = [0, 5, 10];
        assert_eq!(match_region(&starts, 14, 1, 4), Some(0));
        assert_eq!(match_region(&starts, 14, 5, 8), Some(1));
        assert_eq!(match_region(&starts, 14, 2, 2), None);
        assert_eq!(match_region(&starts, 14, 4, 6), None);
    }

    #[test]
    fn match_region_rejects_separator_only_and_separator_touching_hits() {
        let chunks = [
            keyhog_core::Chunk::from("abcd"),
            keyhog_core::Chunk::from("wxyz"),
        ];
        let mut scratch = Phase2GpuDfaScratch::default();
        build_packed_region_batch(&chunks, &mut scratch).expect("region batch");
        assert_eq!(scratch.haystack, b"abcd\0wxyz");
        assert_eq!(scratch.region_starts, &[0, 5]);

        assert_eq!(
            match_region(&scratch.region_starts, scratch.haystack.len(), 0, 4),
            Some(0)
        );
        assert_eq!(
            match_region(&scratch.region_starts, scratch.haystack.len(), 5, 9),
            Some(1)
        );
        assert_eq!(
            match_region(&scratch.region_starts, scratch.haystack.len(), 4, 5),
            None,
            "the separator byte between regions must not admit the previous chunk"
        );
        assert_eq!(
            match_region(&scratch.region_starts, scratch.haystack.len(), 3, 5),
            None,
            "a match that includes the separator tail must not admit a chunk"
        );
        assert_eq!(
            match_region(&scratch.region_starts, scratch.haystack.len(), 4, 6),
            None,
            "a match that spans the separator into the next chunk must not admit either chunk"
        );
    }

    #[test]
    fn program_kind_is_backend_keyed() {
        assert_eq!(
            Phase2GpuDfaProgramKind::for_backend_id(Some("cuda")),
            Phase2GpuDfaProgramKind::CudaCompatible
        );
        assert_eq!(
            Phase2GpuDfaProgramKind::for_backend_id(Some("vulkan")),
            Phase2GpuDfaProgramKind::SubgroupCoalesced
        );
        assert_eq!(
            Phase2GpuDfaProgramKind::for_backend_id(None),
            Phase2GpuDfaProgramKind::SubgroupCoalesced
        );
        assert!(!Phase2GpuDfaProgramKind::CudaCompatible.use_subgroup_coalesce());
        assert!(Phase2GpuDfaProgramKind::SubgroupCoalesced.use_subgroup_coalesce());
    }

    #[test]
    fn gpu_dfa_candidate_selection_prefers_base_detector_breadth() {
        let patterns = vec![
            (
                test_pattern_with_shape("glyph0[0-9]{2}", false, 0, true),
                Vec::new(),
            ),
            (
                test_pattern_with_shape("base0[0-9]{2}", true, 0, false),
                Vec::new(),
            ),
            (
                test_pattern_with_shape("glyph1[0-9]{2}", false, 1, true),
                Vec::new(),
            ),
            (
                test_pattern_with_shape("base2[0-9]{2}", true, 2, false),
                Vec::new(),
            ),
            (
                test_pattern_with_shape("base2b[0-9]{2}", true, 2, false),
                Vec::new(),
            ),
        ];
        let candidates = [0, 1, 2, 3, 4];

        assert_eq!(
            prioritized_phase2_gpu_dfa_candidates(&patterns, &candidates, 3),
            vec![1, 3, 4],
            "bounded GPU DFA admission must spend slots on base detector regexes before generated homoglyph variants"
        );
        assert_eq!(
            prioritized_phase2_gpu_dfa_candidates(&patterns, &candidates, 5),
            vec![1, 3, 4, 0, 2],
            "homoglyph variants stay eligible after the base-pattern breadth pass"
        );
    }

    #[test]
    fn gpu_dfa_candidate_selection_drops_corrupt_indices_before_prioritization() {
        let patterns = vec![
            (
                test_pattern_with_shape("base0[0-9]{2}", true, 0, false),
                Vec::new(),
            ),
            (
                test_pattern_with_shape("base1[0-9]{2}", true, 1, false),
                Vec::new(),
            ),
        ];
        let candidates = [usize::MAX, 1, 9, 0];

        assert_eq!(
            valid_phase2_gpu_dfa_candidates(&patterns, &candidates),
            vec![1, 0],
            "corrupt GPU DFA candidate indices must be filtered once before selection"
        );
        assert_eq!(
            prioritized_phase2_gpu_dfa_candidates(&patterns, &candidates, 8),
            vec![1, 0],
            "candidate prioritization must not silently carry impossible phase-2 indices"
        );
    }

    #[test]
    fn regex_dfa_source_preserves_detector_case_policy() {
        let detector = test_pattern("abc[0-9]{2}", true);
        let plain = test_pattern("abc[0-9]{2}", false);

        assert_eq!(
            regex_dfa_source_for_pattern(&detector).as_ref(),
            "(?i:abc[0-9]{2})",
            "detector regexes are compiled case-insensitive on the CPU path and must lower the same way for GPU DFA admission"
        );
        assert_eq!(
            regex_dfa_source_for_pattern(&plain).as_ref(),
            "abc[0-9]{2}",
            "plain homoglyph variants must stay case-sensitive when lowered"
        );
    }

    #[test]
    fn replayed_gpu_dfa_admission_matches_cpu_regex_case_policy() {
        let patterns = vec![(test_pattern("abc[0-9]{2}", true), Vec::new())];
        let catalog = Phase2GpuDfaCatalog::build_from_selected_candidates(
            &patterns,
            1,
            &[0],
            Phase2GpuDfaProgramKind::CudaCompatible,
        )
        .expect("case-insensitive detector pattern should lower");
        let chunks = [
            keyhog_core::Chunk::from("prefix ABC12 suffix"),
            keyhog_core::Chunk::from("prefix abc34 suffix"),
            keyhog_core::Chunk::from("prefix xyz99 suffix"),
        ];
        let gpu_admitted = replay_catalog_admission(&catalog, &chunks);
        let cpu_admitted: Vec<bool> = chunks
            .iter()
            .map(|chunk| patterns[0].0.regex.get().is_match(&chunk.data))
            .collect();

        assert_eq!(
            gpu_admitted, cpu_admitted,
            "GPU regex-DFA admission must mirror the detector LazyRegex case policy"
        );
        assert_eq!(gpu_admitted, vec![true, true, false]);
    }

    #[test]
    fn replayed_gpu_dfa_admission_keeps_plain_patterns_case_sensitive() {
        let patterns = vec![(test_pattern("abc[0-9]{2}", false), Vec::new())];
        let catalog = Phase2GpuDfaCatalog::build_from_selected_candidates(
            &patterns,
            1,
            &[0],
            Phase2GpuDfaProgramKind::CudaCompatible,
        )
        .expect("plain pattern should lower");
        let chunks = [
            keyhog_core::Chunk::from("prefix ABC12 suffix"),
            keyhog_core::Chunk::from("prefix abc34 suffix"),
        ];
        let gpu_admitted = replay_catalog_admission(&catalog, &chunks);
        let cpu_admitted: Vec<bool> = chunks
            .iter()
            .map(|chunk| patterns[0].0.regex.get().is_match(&chunk.data))
            .collect();

        assert_eq!(
            gpu_admitted, cpu_admitted,
            "plain phase-2 variants must not become case-insensitive in the GPU DFA catalog"
        );
        assert_eq!(gpu_admitted, vec![false, true]);
    }

    #[test]
    fn embedded_detector_set_builds_real_gpu_dfa_catalog_slice() {
        let detectors = keyhog_core::load_embedded_detectors_or_fail()
            .expect("embedded detector corpus must parse");
        let scanner =
            CompiledScanner::compile_with_gpu_policy(detectors, GpuInitPolicy::ForceDisabled)
                .expect("embedded detector corpus must compile without GPU acquisition");
        let candidates = prefixless_always_active_candidates(
            &scanner.phase2_patterns,
            &scanner.phase2_always_active_indices,
        );
        assert!(
            !candidates.is_empty(),
            "embedded detector corpus must include prefixless always-active phase-2 candidates \
             for KH-VYRE-5 GPU regex-DFA coverage"
        );
        let selected = prioritized_phase2_gpu_dfa_candidates(
            &scanner.phase2_patterns,
            &candidates,
            PHASE2_GPU_DFA_MAX_CANDIDATES,
        );
        assert_eq!(
            selected.len(),
            candidates.len().min(PHASE2_GPU_DFA_MAX_CANDIDATES),
            "production GPU DFA selection must fill the configured shard budget when the embedded corpus has enough candidates"
        );
        let selected_len = selected.len().min(8);
        let catalog = Phase2GpuDfaCatalog::build_from_selected_candidates(
            &scanner.phase2_patterns,
            candidates.len(),
            &selected[..selected_len],
            Phase2GpuDfaProgramKind::CudaCompatible,
        )
        .expect("selected embedded prefixless phase-2 candidates must lower to at least one GPU DFA shard");
        let covered: usize = catalog
            .shards
            .iter()
            .map(|shard| shard.phase2_indices.len())
            .sum();
        assert!(
            covered > 0,
            "selected embedded prefixless phase-2 candidates produced no GPU DFA coverage"
        );
        assert!(
            covered <= selected_len,
            "GPU DFA catalog covered more patterns than selected: covered={covered}, selected={selected_len}"
        );
        assert!(
            catalog.uncovered_patterns + covered >= candidates.len(),
            "uncovered/covered accounting must include the full embedded prefixless candidate set"
        );
    }
}
