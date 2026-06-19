//! GPU regex-DFA admission for prefixless always-active phase-2 patterns.
//!
//! This is deliberately an admission accelerator, not a replacement for the
//! phase-2 extractor. A GPU hit only says "this chunk must run the shared
//! phase-2 tail"; extraction still uses the existing CPU regex path so recall,
//! confidence, suppression, and reporting stay under one owner. A GPU miss is
//! trusted only as "no covered prefixless pattern was seen"; uncovered patterns
//! and dispatch failures continue through the CPU admission gate.

use super::phase2::gate_prefix_literals;
use super::*;
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::OnceLock;

const PHASE2_GPU_DFA_MAX_MATCHES: u32 = 1 << 20;
const PHASE2_GPU_DFA_MAX_STATES: usize = 16_384;
const PHASE2_GPU_DFA_TARGET_SHARD_PATTERNS: usize = 16;
const PHASE2_GPU_DFA_MAX_SHARDS: usize = 16;
const PHASE2_GPU_DFA_MAX_CANDIDATES: usize =
    PHASE2_GPU_DFA_TARGET_SHARD_PATTERNS * PHASE2_GPU_DFA_MAX_SHARDS;
const MATCH_TRIPLE_BYTES: usize = 12;

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

#[derive(Debug)]
struct Phase2GpuDfaShard {
    pipeline: vyre_libs::scan::RegexDfaPipeline,
    phase2_indices: Vec<usize>,
}

#[derive(Default)]
struct Phase2GpuDfaScratch {
    haystack: Vec<u8>,
    region_starts: Vec<u32>,
    dispatch: vyre_libs::scan::dispatch_io::ScanDispatchScratch,
    matches: Vec<vyre_libs::scan::LiteralMatch>,
}

thread_local! {
    static PHASE2_GPU_DFA_SCRATCH: RefCell<Phase2GpuDfaScratch> =
        RefCell::new(Phase2GpuDfaScratch::default());
}

struct ZeroPhase2GpuDfaScratch<'a> {
    scratch: &'a mut Phase2GpuDfaScratch,
}

impl<'a> ZeroPhase2GpuDfaScratch<'a> {
    fn new(scratch: &'a mut Phase2GpuDfaScratch) -> Self {
        Self { scratch }
    }
}

impl Drop for ZeroPhase2GpuDfaScratch<'_> {
    fn drop(&mut self) {
        self.scratch.haystack.fill(0);
        self.scratch.haystack.clear();
        self.scratch.region_starts.clear();
        self.scratch.dispatch.haystack_bytes.fill(0);
        self.scratch.dispatch.haystack_bytes.clear();
        self.scratch.dispatch.hit_bytes.fill(0);
        self.scratch.dispatch.hit_bytes.clear();
        self.scratch.matches.clear();
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
            return None;
        }
        if uncovered_patterns > 0 {
            tracing::warn!(
                target: "keyhog::gpu",
                covered = covered_patterns,
                uncovered = uncovered_patterns,
                "phase-2 GPU regex-DFA admission has uncovered prefixless pattern(s); GPU hits can admit chunks, misses still consult CPU admission"
            );
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

    pub(crate) fn scan_admission(
        &self,
        backend: &dyn vyre::VyreBackend,
        chunks: &[keyhog_core::Chunk],
    ) -> std::result::Result<Phase2GpuDfaAdmission, String> {
        if chunks.is_empty() || self.shards.is_empty() {
            return Ok(Phase2GpuDfaAdmission {
                admitted: vec![false; chunks.len()],
                complete: true,
                matches_seen: 0,
            });
        }
        PHASE2_GPU_DFA_SCRATCH
            .try_with(|cell| {
                let mut scratch = cell.try_borrow_mut().map_err(|_| {
                    "phase-2 GPU regex-DFA scratch already borrowed on this thread; recursive \
                     phase-2 GPU admission dispatch is unsupported"
                        .to_string()
                })?;
                let zero_on_drop = ZeroPhase2GpuDfaScratch::new(&mut scratch);
                build_raw_region_batch(chunks, zero_on_drop.scratch)?;
                self.scan_admission_with_scratch(backend, zero_on_drop.scratch, chunks.len())
            })
            .map_err(|_| {
                "phase-2 GPU regex-DFA scratch unavailable during thread shutdown".to_string()
            })?
    }

    fn scan_admission_with_scratch(
        &self,
        backend: &dyn vyre::VyreBackend,
        scratch: &mut Phase2GpuDfaScratch,
        chunk_count: usize,
    ) -> std::result::Result<Phase2GpuDfaAdmission, String> {
        let mut admitted = vec![false; chunk_count];
        let mut complete = self.uncovered_patterns == 0;
        let mut matches_seen = 0usize;
        for shard in &self.shards {
            let overflowed = shard.scan_admission_into(backend, scratch, &mut admitted)?;
            matches_seen = matches_seen.saturating_add(scratch.matches.len());
            if overflowed {
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

fn prefixless_always_active_candidates(
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
    always_active_indices: &[usize],
) -> Vec<usize> {
    always_active_indices
        .iter()
        .copied()
        .filter(|&idx| {
            phase2_patterns
                .get(idx)
                .is_some_and(|(pattern, _)| gate_prefix_literals(pattern.regex.as_str()).is_none())
        })
        .collect()
}

fn prioritized_phase2_gpu_dfa_candidates(
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
    candidates: &[usize],
    max_candidates: usize,
) -> Vec<usize> {
    let mut selected = Vec::with_capacity(candidates.len().min(max_candidates));
    let mut selected_indices = HashSet::new();
    let mut base_detectors = HashSet::new();
    let mut homoglyph_detectors = HashSet::new();

    append_phase2_gpu_dfa_candidates(
        phase2_patterns,
        candidates,
        max_candidates,
        &mut selected,
        &mut selected_indices,
        |pattern| !pattern.homoglyph_variant && base_detectors.insert(pattern.detector_index),
    );
    append_phase2_gpu_dfa_candidates(
        phase2_patterns,
        candidates,
        max_candidates,
        &mut selected,
        &mut selected_indices,
        |pattern| !pattern.homoglyph_variant,
    );
    append_phase2_gpu_dfa_candidates(
        phase2_patterns,
        candidates,
        max_candidates,
        &mut selected,
        &mut selected_indices,
        |pattern| pattern.homoglyph_variant && homoglyph_detectors.insert(pattern.detector_index),
    );
    append_phase2_gpu_dfa_candidates(
        phase2_patterns,
        candidates,
        max_candidates,
        &mut selected,
        &mut selected_indices,
        |_| true,
    );

    selected
}

fn append_phase2_gpu_dfa_candidates<F>(
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
    candidates: &[usize],
    max_candidates: usize,
    selected: &mut Vec<usize>,
    selected_indices: &mut HashSet<usize>,
    mut accepts: F,
) where
    F: FnMut(&CompiledPattern) -> bool,
{
    if selected.len() >= max_candidates {
        return;
    }
    for &idx in candidates {
        if selected.len() >= max_candidates {
            return;
        }
        let Some((pattern, _)) = phase2_patterns.get(idx) else {
            continue;
        };
        if selected_indices.contains(&idx) || !accepts(pattern) {
            continue;
        }
        selected.push(idx);
        selected_indices.insert(idx);
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

impl CompiledScanner {
    pub(crate) fn phase2_gpu_dfa_catalog(
        &self,
        backend_id: Option<&'static str>,
    ) -> Option<&Phase2GpuDfaCatalog> {
        self.phase2_gpu_dfa.catalog(
            &self.phase2_patterns,
            &self.phase2_always_active_indices,
            backend_id,
        )
    }
}

impl Phase2GpuDfaShard {
    fn scan_admission_into(
        &self,
        backend: &dyn vyre::VyreBackend,
        scratch: &mut Phase2GpuDfaScratch,
        admitted: &mut [bool],
    ) -> std::result::Result<bool, String> {
        use vyre_libs::scan::dispatch_io;

        let haystack_len = dispatch_io::scan_guard(
            &scratch.haystack,
            "phase2_gpu_regex_dfa",
            dispatch_io::DEFAULT_MAX_SCAN_BYTES,
        )
        .map_err(|error| error.to_string())?;
        dispatch_io::pack_haystack_u32_into(
            &scratch.haystack,
            &mut scratch.dispatch.haystack_bytes,
        )
        .map_err(|error| error.to_string())?;
        let transition_bytes = dispatch_io::u32_words_as_le_bytes(&self.pipeline.dfa.transitions);
        let output_offset_bytes =
            dispatch_io::u32_words_as_le_bytes(&self.pipeline.dfa.output_offsets);
        let output_record_bytes =
            dispatch_io::u32_words_as_le_bytes(&self.pipeline.dfa.output_records);
        let pattern_length_bytes =
            dispatch_io::u32_words_as_le_bytes(&self.pipeline.pattern_lengths);
        let haystack_len_bytes = haystack_len.to_le_bytes();
        let match_count_bytes = [0u8; 4];
        let config = dispatch_io::byte_scan_dispatch_config(
            haystack_len,
            self.pipeline.program.workgroup_size[0],
        );
        let inputs = [
            scratch.dispatch.haystack_bytes.as_slice(),
            transition_bytes.as_ref(),
            output_offset_bytes.as_ref(),
            output_record_bytes.as_ref(),
            pattern_length_bytes.as_ref(),
            haystack_len_bytes.as_slice(),
            match_count_bytes.as_slice(),
        ];
        let outputs = backend
            .dispatch_borrowed(&self.pipeline.program, &inputs, &config)
            .map_err(|error| error.to_string())?;
        let count_bytes =
            dispatch_io::try_output_bytes(&outputs, 0, "phase-2 GPU regex-DFA match count")
                .map_err(|error| error.to_string())?;
        let count =
            dispatch_io::try_read_u32_prefix(count_bytes, "phase-2 GPU regex-DFA match count")
                .map_err(|error| error.to_string())?;
        let triples_bytes =
            dispatch_io::try_output_bytes(&outputs, 1, "phase-2 GPU regex-DFA matches")
                .map_err(|error| error.to_string())?;
        let overflowed = count > PHASE2_GPU_DFA_MAX_MATCHES;
        let decoded_count = count.min(PHASE2_GPU_DFA_MAX_MATCHES);
        let decoded_count_usize = usize::try_from(decoded_count).map_err(|error| {
            format!(
                "phase-2 GPU regex-DFA match count {} exceeds host usize: {error}",
                decoded_count
            )
        })?;
        let required = decoded_count_usize
            .checked_mul(MATCH_TRIPLE_BYTES)
            .ok_or_else(|| {
                "phase-2 GPU regex-DFA match decode byte count overflowed host usize".to_string()
            })?;
        if triples_bytes.len() < required {
            return Err(format!(
                "phase-2 GPU regex-DFA match readback was {} byte(s), need {} byte(s)",
                triples_bytes.len(),
                required
            ));
        }
        dispatch_io::try_unpack_match_triples_exact_prefix_into(
            triples_bytes,
            decoded_count,
            &mut scratch.matches,
        )
        .map_err(|error| error.to_string())?;

        for m in &scratch.matches {
            if self.phase2_indices.get(m.pattern_id as usize).is_none() {
                return Err(format!(
                    "phase-2 GPU regex-DFA reported pattern id {} outside shard size {}",
                    m.pattern_id,
                    self.phase2_indices.len()
                ));
            };
            if let Some(region) = match_region(
                &scratch.region_starts,
                scratch.haystack.len(),
                m.start,
                m.end,
            ) {
                if let Some(slot) = admitted.get_mut(region) {
                    *slot = true;
                }
            }
        }
        if overflowed {
            tracing::warn!(
                target: "keyhog::gpu",
                count,
                cap = PHASE2_GPU_DFA_MAX_MATCHES,
                "phase-2 GPU regex-DFA admission hit cap; decoded hits can admit chunks, misses still consult CPU admission"
            );
        }
        Ok(overflowed)
    }
}

pub(crate) struct Phase2GpuDfaAdmission {
    pub(crate) admitted: Vec<bool>,
    pub(crate) complete: bool,
    pub(crate) matches_seen: usize,
}

fn build_shards_recursive(
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
    indices: &[usize],
    use_subgroup_coalesce: bool,
    shards: &mut Vec<Phase2GpuDfaShard>,
    uncovered_patterns: &mut usize,
) {
    if indices.is_empty() {
        return;
    }
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

fn build_shard(
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
    indices: &[usize],
    use_subgroup_coalesce: bool,
) -> std::result::Result<Phase2GpuDfaShard, String> {
    let mut sources = Vec::with_capacity(indices.len());
    for &idx in indices {
        let (pattern, _) = phase2_patterns
            .get(idx)
            .ok_or_else(|| format!("phase-2 index {idx} is out of range"))?;
        sources.push(regex_dfa_source_for_pattern(pattern));
    }
    let source_refs: Vec<&str> = sources.iter().map(|source| source.as_ref()).collect();
    let mut pipeline = vyre_libs::scan::build_regex_dfa_unanchored(
        &source_refs,
        PHASE2_GPU_DFA_MAX_MATCHES,
        PHASE2_GPU_DFA_MAX_STATES,
    )
    .map_err(|error| error.to_string())?;
    if !use_subgroup_coalesce {
        pipeline.program = vyre_libs::scan::classic_ac::try_build_ac_bounded_ranges_program_ext(
            &pipeline.dfa,
            u32::try_from(source_refs.len()).map_err(|error| {
                format!(
                    "phase-2 GPU regex-DFA shard pattern count {} exceeds u32 ABI: {error}",
                    source_refs.len()
                )
            })?,
            PHASE2_GPU_DFA_MAX_MATCHES,
            false,
        )
        .map_err(|error| {
            format!("phase-2 GPU regex-DFA CUDA-compatible program build failed: {error}")
        })?;
    }
    Ok(Phase2GpuDfaShard {
        pipeline,
        phase2_indices: indices.to_vec(),
    })
}

fn regex_dfa_source_for_pattern(pattern: &CompiledPattern) -> Cow<'_, str> {
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

fn build_raw_region_batch(
    chunks: &[keyhog_core::Chunk],
    scratch: &mut Phase2GpuDfaScratch,
) -> std::result::Result<(), String> {
    let mut total = chunks.len().saturating_sub(1);
    for chunk in chunks {
        total = total.checked_add(chunk.data.len()).ok_or_else(|| {
            "phase-2 GPU regex-DFA coalesced batch length overflows host usize".to_string()
        })?;
    }
    if total > u32::MAX as usize {
        return Err(format!(
            "phase-2 GPU regex-DFA coalesced batch is {total} byte(s), above the u32 GPU ABI; split the batch before dispatch"
        ));
    }
    scratch.haystack.clear();
    scratch.region_starts.clear();
    scratch
        .haystack
        .try_reserve(total)
        .map_err(|error| format!("phase-2 GPU regex-DFA haystack reserve failed: {error}"))?;
    scratch
        .region_starts
        .try_reserve(chunks.len())
        .map_err(|error| format!("phase-2 GPU regex-DFA region-start reserve failed: {error}"))?;
    for (idx, chunk) in chunks.iter().enumerate() {
        let start = u32::try_from(scratch.haystack.len()).map_err(|_| {
            "phase-2 GPU regex-DFA region start exceeds the u32 GPU ABI".to_string()
        })?;
        scratch.region_starts.push(start);
        scratch.haystack.extend_from_slice(chunk.data.as_bytes());
        if idx + 1 != chunks.len() {
            scratch.haystack.push(0);
        }
    }
    Ok(())
}

fn match_region(region_starts: &[u32], haystack_len: usize, start: u32, end: u32) -> Option<usize> {
    if end <= start {
        return None;
    }
    let start_region = region_for_offset(region_starts, start)?;
    let last = end.saturating_sub(1);
    let end_region = region_for_offset(region_starts, last)?;
    if start_region != end_region {
        tracing::warn!(
            target: "keyhog::gpu",
            start,
            end,
            "phase-2 GPU regex-DFA match crossed a coalesced region boundary; ignoring admission hit"
        );
        return None;
    }
    let next_start = region_starts
        .get(start_region + 1)
        .map_or(haystack_len, |&offset| offset as usize);
    let start_usize = match usize::try_from(start) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(
                target: "keyhog::gpu",
                start,
                %error,
                "phase-2 GPU regex-DFA match start does not fit host usize; ignoring admission hit"
            );
            return None;
        }
    };
    if start_usize < next_start {
        Some(start_region)
    } else {
        tracing::warn!(
            target: "keyhog::gpu",
            start,
            end,
            region = start_region,
            next_start,
            "phase-2 GPU regex-DFA match starts outside its coalesced region; ignoring admission hit"
        );
        None
    }
}

fn region_for_offset(region_starts: &[u32], offset: u32) -> Option<usize> {
    if region_starts.is_empty() {
        return None;
    }
    region_starts
        .partition_point(|&start| start <= offset)
        .checked_sub(1)
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
            homoglyph_variant,
        }
    }

    fn replay_catalog_admission(
        catalog: &Phase2GpuDfaCatalog,
        chunks: &[keyhog_core::Chunk],
    ) -> Vec<bool> {
        let mut scratch = Phase2GpuDfaScratch::default();
        build_raw_region_batch(chunks, &mut scratch).expect("region batch");
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
    fn raw_region_batch_preserves_case_separates_and_clears() {
        let chunks = [
            keyhog_core::Chunk::from("GhP_TOKEN"),
            keyhog_core::Chunk::from("Zz9"),
        ];
        let mut scratch = Phase2GpuDfaScratch::default();
        {
            let guard = ZeroPhase2GpuDfaScratch::new(&mut scratch);
            build_raw_region_batch(&chunks, guard.scratch).expect("batch");
            assert_eq!(guard.scratch.haystack, b"GhP_TOKEN\0Zz9");
            assert_eq!(guard.scratch.region_starts, &[0, 10]);
        }
        assert!(scratch.haystack.is_empty());
        assert!(scratch.region_starts.is_empty());
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
