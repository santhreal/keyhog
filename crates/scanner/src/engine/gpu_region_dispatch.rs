//! Live wiring of the coalesced GPU literal-region trigger path.
//!
//! One resident VYRE dispatch produces detector presence plus positions for the
//! shared confirmed-anchor and generic-keyword localizers. Presence becomes the
//! same per-chunk trigger bitmap the Hyperscan prefilter produces; positions are
//! optional evidence consumed by the same phase-two implementations that would
//! otherwise collect them on the CPU. Regex extraction, entropy, ML,
//! suppression, deduplication, recovery, and boundary scans retain one owner.
//!
//! Recall + precision: GPU presence only admits candidate detector bits and GPU
//! positions only replace equivalent CPU localization. Phase 2 still validates
//! every candidate with the real detector regex. The full CPU
//! Hyperscan trigger floor is not part of the default fast path; it is enabled
//! only for explicit parity/debug runs.

use super::gpu_region_batch::{
    for_each_region_presence_batch, for_each_region_presence_window,
    region_presence_batch_byte_limit, set_trigger_bit, trigger_bit_is_set, validate_detector_match,
    validate_region_presence_request_plan, RegionPresenceBatchMode,
    MAX_REGION_PRESENCE_REQUEST_DISPATCHES,
};
#[cfg(test)]
use super::gpu_region_dispatch_helpers::record_test_window_reduction_allocation;
#[cfg(test)]
pub(super) use super::gpu_region_dispatch_helpers::{
    append_phase2_gpu_admission, reset_test_window_reduction_allocations,
    test_window_reduction_allocations,
};
use super::gpu_region_dispatch_helpers::{
    mib_per_second, scan_phase2_gpu_chunks_sharded, scan_phase2_gpu_refs_sharded,
};
#[cfg(test)]
use super::phase2_gpu_dfa::{build_phase2_gpu_admission_workload, Phase2GpuDfaAdmission};
use super::phase2_gpu_dfa::{
    build_phase2_gpu_admission_workload_filtered, expand_phase2_gpu_admission,
    validate_phase2_gpu_trigger_rows, Phase2GpuAdmissionWorkload,
};
use super::*;

impl CompiledScanner {
    pub(crate) fn phase2_gpu_dfa_catalog(
        &self,
        backend_id: Option<&'static str>,
    ) -> Option<&super::phase2_gpu_dfa::Phase2GpuDfaCatalog> {
        self.phase2_gpu_dfa.catalog(
            &self.phase2_patterns,
            &self.phase2_always_active_indices,
            backend_id,
        )
    }

    /// Coalesced GPU region-presence scan: bounded GPU dispatches over the
    /// `chunks` batch produce the per-chunk trigger bitmap, then the SHARED
    /// coalesced phase-2 tail runs the identical per-chunk extraction every
    /// other backend uses. This infallible direct-library wrapper exits when
    /// dispatch fails; production orchestrators use the fallible companion so
    /// they can replay the same stable bytes and report the recovery.
    pub(crate) fn scan_coalesced_gpu_region_presence(
        &self,
        chunks: &[keyhog_core::Chunk],
        backend: crate::hw_probe::ScanBackend,
        route: crate::ScanExecutionRoute,
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        match self.try_scan_coalesced_gpu_region_presence(chunks, backend, route) {
            Ok(results) => results,
            Err(error) => super::gpu_forced::fail_selected_gpu_dispatch_error(self, error),
        }
    }

    /// Result-returning production GPU boundary. CLI orchestrators consume the
    /// error in-band to recover stable input; health diagnostics consume it to
    /// emit a complete report. Only the infallible direct-library wrapper maps
    /// it to the process-level explicit-backend contract.
    pub(crate) fn try_scan_coalesced_gpu_region_presence(
        &self,
        chunks: &[keyhog_core::Chunk],
        route: crate::hw_probe::ScanBackend,
        execution_route: crate::ScanExecutionRoute,
    ) -> std::result::Result<
        Vec<Vec<keyhog_core::RawMatch>>,
        super::gpu_forced::SelectedGpuDispatchError,
    > {
        if chunks.is_empty() {
            return Ok(Vec::new());
        }

        let dispatch_failure =
            |reason: String| Err(super::gpu_forced::SelectedGpuDispatchError::new(reason));

        // The shared coalesced phase-2 tail is `#[cfg(feature = "simd")]` (it is
        // the Hyperscan path's extraction). `gpu` implies `simd` at the feature
        // level (see keyhog-scanner Cargo.toml: `gpu = ["simd", ...]`), so this
        // body is ALWAYS compiled under `gpu` and the region-presence path always
        // has its tail. The `#[cfg(feature = "simd")]` is retained as a fail-closed
        // assertion of that invariant: were the dependency ever dropped, this
        // function would fail to compile rather than silently lose its tail.
        #[cfg(feature = "simd")]
        {
            let kh = super::profile::perf_trace_enabled();
            let t_matcher = std::time::Instant::now();
            let Some(matcher) = self.gpu_matcher() else {
                return dispatch_failure(
                    "gpu literal matcher not built for coalesced region scan".to_string(),
                );
            };
            let matcher_s = t_matcher.elapsed();
            let Some(backend) = self.gpu_backends.get(route) else {
                return dispatch_failure(format!(
                    "{} was selected but its driver was not acquired",
                    route.label()
                ));
            };
            let Some(resident_slot) = self.gpu_resident_literal_slot(route) else {
                return dispatch_failure(format!(
                    "{} has no scanner-owned resident pipeline slot",
                    route.label()
                ));
            };

            let words = self.ac_map.len().div_ceil(64).max(1);
            let gpu_literal_count = self.gpu_literal_count();
            let presence_words = gpu_literal_count.div_ceil(32).max(1);
            let region_source_bytes = chunks.iter().try_fold(0usize, |total, chunk| {
                total.checked_add(chunk.data.len()).ok_or_else(|| {
                    super::gpu_forced::SelectedGpuDispatchError::new(
                        "GPU region-presence source-byte accounting overflows host usize"
                            .to_string(),
                    )
                })
            })?;
            let t_co = std::time::Instant::now();
            let mut dis_s = std::time::Duration::ZERO;
            let mut derive_s_total = std::time::Duration::ZERO;
            let region_dispatch_profile = super::profile::span(super::profile::P::BackendDispatch);
            let mut triggers: Vec<Option<Vec<u64>>> = Vec::new();
            let mut phase2_keyword_hints: Vec<Vec<u32>> = Vec::new();
            let mut phase2_always_anchor_presence: Vec<bool> = Vec::new();
            let positioned_base = self.ac_map.len()
                + self.phase2_keyword_count
                + self.phase2_always_anchor_literal_count;
            let confirmed_position_end = positioned_base + self.confirmed_anchor_literal_count;
            let generic_position_end = confirmed_position_end + self.generic_keyword_literal_count;
            let mut confirmed_anchor_literal_matches = (self.confirmed_anchor_literal_count > 0)
                .then(|| vec![Vec::<(u32, u32)>::new(); chunks.len()]);
            let mut generic_keyword_positions = (self.generic_keyword_literal_count > 0)
                .then(|| vec![Vec::<u32>::new(); chunks.len()]);
            triggers.try_reserve(chunks.len()).map_err(|error| {
                super::gpu_forced::SelectedGpuDispatchError::new(format!(
                    "GPU region-presence trigger-row reserve failed: {error}"
                ))
            })?;
            phase2_keyword_hints
                .try_reserve(chunks.len())
                .map_err(|error| {
                    super::gpu_forced::SelectedGpuDispatchError::new(format!(
                        "GPU phase-2 keyword-hint row reserve failed: {error}"
                    ))
                })?;
            phase2_always_anchor_presence
                .try_reserve(chunks.len())
                .map_err(|error| {
                    super::gpu_forced::SelectedGpuDispatchError::new(format!(
                        "GPU phase-2 anchor-presence row reserve failed: {error}"
                    ))
                })?;
            let mut gpu_presence_bits = 0usize;
            let mut logical_derive_s = std::time::Duration::ZERO;
            let mut derive_presence_row = |row: &[u32]| -> std::result::Result<(), String> {
                let whole_presence_words = positioned_base / 32;
                let tail_presence_bits = positioned_base % 32;
                let whole_bits = row
                    .iter()
                    .take(whole_presence_words)
                    .map(|word| word.count_ones() as usize)
                    .sum::<usize>();
                let tail_bits = if tail_presence_bits == 0 {
                    0
                } else {
                    row.get(whole_presence_words).map_or(0, |word| {
                        (word & ((1u32 << tail_presence_bits) - 1)).count_ones() as usize
                    })
                };
                gpu_presence_bits = gpu_presence_bits
                    .checked_add(whole_bits + tail_bits)
                    .ok_or_else(|| {
                        "region-presence reduced bit count overflows host usize".to_string()
                    })?;
                let bits = self.triggered_patterns_from_gpu_presence(row);
                phase2_keyword_hints.push(self.phase2_keyword_hints_from_gpu_presence(row));
                phase2_always_anchor_presence
                    .push(self.phase2_always_anchor_present_from_gpu_presence(row));
                triggers.push(bits.iter().any(|&word| word != 0).then_some(bits));
                Ok(())
            };
            let mut dispatch_presence = |haystack: &[u8],
                                         region_starts: &[u32],
                                         logical_start: usize,
                                         rows: usize,
                                         logical_byte_base: usize,
                                         consume: &mut dyn FnMut(
                &[u32],
            )
                -> std::result::Result<
                (),
                String,
            >| {
                let t_dis = std::time::Instant::now();
                let expected_presence_words =
                    rows.checked_mul(presence_words).ok_or_else(|| {
                        "region-presence physical readback size overflows host usize".to_string()
                    })?;
                let logical_end = logical_start.checked_add(rows).ok_or_else(|| {
                    "region-presence logical row range overflows host usize".to_string()
                })?;
                let mut derive_s = std::time::Duration::ZERO;
                let result =
                    super::gpu_resident_evidence::scan_gpu_literal_evidence_by_region_resident(
                        resident_slot,
                        matcher,
                        backend,
                        haystack,
                        region_starts,
                        |presence, literal_matches| {
                            let t_derive = std::time::Instant::now();
                            if presence.len() != expected_presence_words {
                                return Err(format!(
                                    "region-presence readback for logical chunks {logical_start}..{} returned {} u32 word(s), need {expected_presence_words}",
                                        logical_end,
                                        presence.len()
                                    ));
                            }
                            for (shard_row, row) in
                                presence.chunks_exact(presence_words).enumerate()
                            {
                                let row_idx =
                                    logical_start.checked_add(shard_row).ok_or_else(|| {
                                        "region-presence logical row index overflows host usize"
                                            .to_string()
                                    })?;
                                if let Some((word_idx, stray_bits)) =
                                    self.gpu_presence_stray_tail_bits(row)
                                {
                                    return Err(format!(
                                            "region-presence readback row {row_idx} has out-of-range detector bit(s): word {word_idx} bits 0x{stray_bits:08x} beyond {} literal(s)",
                                            gpu_literal_count
                                        ));
                                }
                                consume(row)?;
                            }
                            for literal_match in literal_matches {
                                let pattern_id = literal_match.pattern_id as usize;
                                if pattern_id >= gpu_literal_count {
                                    return Err(format!(
                                        "resident fused literal match returned out-of-range pattern id {pattern_id} for {gpu_literal_count} compiled literal(s)"
                                    ));
                                }
                                if pattern_id < positioned_base {
                                    continue;
                                }
                                let Some(region) = super::phase2_gpu_dfa::match_region(
                                    region_starts,
                                    haystack.len(),
                                    literal_match.start,
                                    literal_match.end,
                                ) else {
                                    return Err(format!(
                                        "resident fused literal match ({}, {}, {}) does not belong to one complete input region",
                                        literal_match.pattern_id,
                                        literal_match.start,
                                        literal_match.end,
                                    ));
                                };
                                let row_idx =
                                    logical_start.checked_add(region).ok_or_else(|| {
                                        "resident fused positioned row index overflows host usize"
                                            .to_string()
                                    })?;
                                let region_start = region_starts[region];
                                let relative_start = literal_match
                                    .start
                                    .checked_sub(region_start)
                                    .ok_or_else(|| {
                                        "resident fused positioned match starts before its attributed region"
                                            .to_string()
                                    })?;
                                let relative_start =
                                    usize::try_from(relative_start).map_err(|_| {
                                        "resident fused positioned match offset exceeds host usize"
                                            .to_string()
                                    })?;
                                let local_start = relative_start
                                    .checked_add(logical_byte_base)
                                    .ok_or_else(|| {
                                        "resident fused positioned logical offset overflows host usize"
                                            .to_string()
                                    })?;
                                let local_start = u32::try_from(local_start).map_err(|_| {
                                    "resident fused positioned match offset exceeds the u32 chunk ABI"
                                        .to_string()
                                })?;
                                if pattern_id < confirmed_position_end {
                                    let rows = confirmed_anchor_literal_matches.as_mut().ok_or_else(|| {
                                        "resident fused confirmed-anchor match has no compiled output owner"
                                            .to_string()
                                    })?;
                                    let literal_id = u32::try_from(pattern_id - positioned_base)
                                        .map_err(|_| {
                                            "resident fused confirmed-anchor literal id exceeds the u32 scanner ABI"
                                                .to_string()
                                        })?;
                                    let row_count = rows.len();
                                    rows.get_mut(row_idx)
                                        .ok_or_else(|| {
                                            format!(
                                                "resident fused confirmed-anchor row {row_idx} exceeds {row_count} logical chunk row(s)"
                                            )
                                        })?
                                        .push((literal_id, local_start));
                                } else if pattern_id < generic_position_end {
                                    if let Some(rows) = generic_keyword_positions.as_mut() {
                                        let row_count = rows.len();
                                        rows.get_mut(row_idx)
                                            .ok_or_else(|| {
                                                format!(
                                                    "resident fused generic-keyword row {row_idx} exceeds {row_count} logical chunk row(s)"
                                                )
                                            })?
                                            .push(local_start);
                                    }
                                }
                            }
                            derive_s = t_derive.elapsed();
                            Ok(())
                        },
                    );
                dis_s += t_dis.elapsed().saturating_sub(derive_s);
                derive_s_total += derive_s;
                result
            };
            let byte_limit = region_presence_batch_byte_limit(backend.id());
            let planned_dispatches =
                validate_region_presence_request_plan(chunks, byte_limit, self.gpu_max_literal_len)
                    .map_err(super::gpu_forced::SelectedGpuDispatchError::new)?;
            let mut region_dispatches = 0usize;
            let mut region_coalesced_bytes = 0usize;
            let mut region_max_dispatch_bytes = 0usize;
            let mut region_batch_mode = RegionPresenceBatchMode::FoldedScratch;
            let mut cursor = 0usize;
            while cursor < chunks.len() {
                let oversized = chunks[cursor].data.len() > byte_limit;
                let (summary, next_cursor) = if oversized {
                    let logical_row = cursor;
                    #[cfg(test)]
                    record_test_window_reduction_allocation();
                    let mut reduced = Vec::new();
                    reduced.try_reserve_exact(presence_words).map_err(|error| {
                        super::gpu_forced::SelectedGpuDispatchError::new(format!(
                            "GPU region-presence window reduction reserve failed: {error}"
                        ))
                    })?;
                    reduced.resize(presence_words, 0u32);
                    let summary = for_each_region_presence_window(
                        chunks[cursor].data.as_bytes(),
                        byte_limit,
                        self.gpu_max_literal_len,
                        |haystack, range| {
                            let mut reduce = |row: &[u32]| -> std::result::Result<(), String> {
                                for (target, &word) in reduced.iter_mut().zip(row) {
                                    *target |= word;
                                }
                                Ok(())
                            };
                            dispatch_presence(
                                haystack,
                                &[0],
                                logical_row,
                                1,
                                range.start,
                                &mut reduce,
                            )
                        },
                    );
                    if summary.is_ok() {
                        let t_derive = std::time::Instant::now();
                        derive_presence_row(&reduced)
                            .map_err(super::gpu_forced::SelectedGpuDispatchError::new)?;
                        logical_derive_s += t_derive.elapsed();
                    }
                    (summary, cursor + 1)
                } else {
                    let run_start = cursor;
                    let run_end = chunks[run_start..]
                        .iter()
                        .position(|chunk| chunk.data.len() > byte_limit)
                        .map_or(chunks.len(), |offset| run_start + offset);
                    (
                        for_each_region_presence_batch(
                            &chunks[run_start..run_end],
                            backend.id(),
                            |haystack, region_starts, _mode, shard| {
                                let logical_start =
                                    run_start.checked_add(shard.chunks.start).ok_or_else(|| {
                                        "region-presence logical shard start overflows host usize"
                                            .to_string()
                                    })?;
                                dispatch_presence(
                                    haystack,
                                    region_starts,
                                    logical_start,
                                    shard.chunks.len(),
                                    0,
                                    &mut derive_presence_row,
                                )
                            },
                        ),
                        run_end,
                    )
                };
                let summary = match summary {
                    Ok(summary) => summary,
                    Err(error) => {
                        drop(region_dispatch_profile);
                        return dispatch_failure(error);
                    }
                };
                region_dispatches = region_dispatches
                    .checked_add(summary.dispatches)
                    .ok_or_else(|| {
                        super::gpu_forced::SelectedGpuDispatchError::new(
                            "GPU region-presence dispatch accounting overflows host usize",
                        )
                    })?;
                if region_dispatches > MAX_REGION_PRESENCE_REQUEST_DISPATCHES {
                    drop(region_dispatch_profile);
                    return dispatch_failure(format!(
                        "GPU region-presence executed {region_dispatches} dispatches, above the preflight request safety limit of {MAX_REGION_PRESENCE_REQUEST_DISPATCHES}"
                    ));
                }
                region_coalesced_bytes = region_coalesced_bytes
                    .checked_add(summary.coalesced_bytes)
                    .ok_or_else(|| {
                        super::gpu_forced::SelectedGpuDispatchError::new(
                            "GPU region-presence byte accounting overflows host usize",
                        )
                    })?;
                region_max_dispatch_bytes =
                    region_max_dispatch_bytes.max(summary.max_dispatch_bytes);
                if oversized {
                    region_batch_mode = RegionPresenceBatchMode::Windowed;
                } else {
                    region_batch_mode = if region_batch_mode == RegionPresenceBatchMode::Windowed {
                        region_batch_mode
                    } else {
                        summary.mode
                    };
                }
                cursor = next_cursor;
            }
            drop(dispatch_presence);
            drop(derive_presence_row);
            if let Some(rows) = confirmed_anchor_literal_matches.as_mut() {
                for row in rows {
                    row.sort_unstable();
                    row.dedup();
                }
            }
            if let Some(rows) = generic_keyword_positions.as_mut() {
                for row in rows {
                    row.sort_unstable();
                    row.dedup();
                }
            }
            derive_s_total += logical_derive_s;
            if region_dispatches != planned_dispatches {
                drop(region_dispatch_profile);
                return dispatch_failure(format!(
                    "GPU region-presence executed {region_dispatches} dispatches after preflighting {planned_dispatches}"
                ));
            }
            if triggers.len() != chunks.len()
                || phase2_keyword_hints.len() != chunks.len()
                || phase2_always_anchor_presence.len() != chunks.len()
            {
                drop(region_dispatch_profile);
                return dispatch_failure(format!(
                    "GPU region-presence derived {} trigger row(s), {} keyword-hint row(s), and {} anchor row(s) for {} logical chunk(s)",
                    triggers.len(),
                    phase2_keyword_hints.len(),
                    phase2_always_anchor_presence.len(),
                    chunks.len()
                ));
            }
            let co_s = t_co
                .elapsed()
                .saturating_sub(dis_s)
                .saturating_sub(derive_s_total);
            drop(region_dispatch_profile);
            let t_floor = std::time::Instant::now();
            let full_recall_floor = self.tuning.gpu_recall_floor_enabled();
            let cpu_triggers = if full_recall_floor {
                match self.simd_prefilter.as_ref() {
                    Some(prefilter) => {
                        Some(self.compute_coalesced_triggers(chunks, prefilter, None))
                    }
                    None => {
                        return dispatch_failure(
                            "gpu_recall_floor requested but no SIMD prefilter is live".to_string(),
                        );
                    }
                }
            } else {
                None
            };

            if triggers.len() != chunks.len() {
                return dispatch_failure(format!(
                    "region-presence readback length mismatch: got {} row(s), need {} row(s)",
                    triggers.len(),
                    chunks.len()
                ));
            }

            let mut gpu_underfire_recovered = 0usize;
            if let Some(cpu_triggers) = cpu_triggers.as_ref() {
                let prepared_text: Vec<std::cell::OnceCell<String>> = (0..chunks.len())
                    .map(|_| std::cell::OnceCell::new())
                    .collect();
                for (ci, cpu_opt) in cpu_triggers.iter().enumerate() {
                    let Some(cpu_bits) = cpu_opt else { continue };
                    if ci >= chunks.len() {
                        break;
                    }
                    for (w, &word) in cpu_bits.iter().enumerate() {
                        let mut rest = word;
                        while rest != 0 {
                            let lo = rest.trailing_zeros() as usize;
                            rest &= rest - 1;
                            let det = w * 64 + lo;
                            if det >= self.ac_map.len() || trigger_bit_is_set(&triggers, ci, det) {
                                continue;
                            }
                            let text = prepared_text[ci].get_or_init(|| {
                                self.prepare_chunk(&chunks[ci])
                                    .preprocessed
                                    .text
                                    .as_ref()
                                    .to_string()
                            });
                            let rx = self.ac_map[det].regex.get();
                            if validate_detector_match(
                                text.as_str(),
                                rx,
                                None,
                                self.ac_match_upper_bounds.get(det).copied().flatten(),
                            ) {
                                set_trigger_bit(&mut triggers, ci, det, words);
                                gpu_underfire_recovered += 1;
                            }
                        }
                    }
                }
            }
            let floor_s = t_floor.elapsed();

            // Surface a GPU under-fire LOUDLY: the GPU DFA missed a real
            // detector match the CPU floor recovered. This is a VYRE literal-set
            // recall bug (region attribution / byte-class edge / divergence) the
            // floor papered over, record it so it is fixed at the source, never
            // hidden (Law 10). One-shot per process to avoid log spam.
            if gpu_underfire_recovered > 0 {
                self.record_gpu_runtime_fault(format!(
                    "GPU region-presence under-fire recovered {gpu_underfire_recovered} \
                     (chunk, detector) pair(s) via CPU recall floor"
                ));
                static UNDERFIRE_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
                if UNDERFIRE_WARNED.set(()).is_ok() {
                    eprintln!(
                        "keyhog: GPU region-presence under-fired on {gpu_underfire_recovered} \
                         (chunk, detector) pair(s) recovered by gpu_recall_floor coverage - fix \
                         the VYRE literal-set path before treating GPU-only as parity-safe."
                    );
                }
                tracing::warn!(
                    target: "keyhog::gpu",
                    recovered = gpu_underfire_recovered,
                    "GPU region-presence under-fire recovered by CPU recall floor (vyre recall bug)",
                );
            }

            if let Err(error) = validate_phase2_gpu_trigger_rows(chunks.len(), triggers.len()) {
                return dispatch_failure(error.to_string());
            }
            let mut phase2_gpu_row_needed = Vec::with_capacity(chunks.len());
            let phase2_gpu_byte_limit = region_presence_batch_byte_limit(backend.id());
            let mut phase2_gpu_excluded_oversized = 0usize;
            let mut phase2_gpu_excluded_non_ascii = 0usize;
            for (idx, chunk) in chunks.iter().enumerate() {
                let row_has_trigger = triggers
                    .get(idx)
                    .and_then(|trigger| trigger.as_ref())
                    .is_some_and(|bits| bits.iter().any(|&word| word != 0));
                if chunk.data.len() > phase2_gpu_byte_limit {
                    phase2_gpu_excluded_oversized += 1;
                    phase2_gpu_row_needed.push(false);
                    continue;
                }
                // The GPU catalog's proof is ASCII-specific. Raw non-ASCII
                // rows may normalize before phase 2 and therefore remain under
                // the canonical CPU admission owner.
                if !chunk.data.is_ascii() {
                    phase2_gpu_excluded_non_ascii += 1;
                    phase2_gpu_row_needed.push(false);
                    continue;
                }
                // Encoded-only rows that CPU admission would route straight to
                // decode-only recovery do not need the prefixless phase-2 GPU
                // DFA. The shared phase-2 tail still runs decode-only on those
                // rows; this just avoids a redundant GPU admission dispatch.
                let decode_only_row = self.chunk_needs_decode_postprocess(chunk)
                    && !self.should_scan_no_hit_chunk(chunk);
                phase2_gpu_row_needed.push(row_has_trigger || !decode_only_row);
            }
            let phase2_gpu_workload =
                build_phase2_gpu_admission_workload_filtered(chunks, |idx, _| {
                    phase2_gpu_row_needed[idx]
                });
            let phase2_dispatch_profile = super::profile::span(super::profile::P::BackendDispatch);
            let t_phase2_gpu = std::time::Instant::now();
            let mut phase2_gpu_empty_complete = false;
            let mut phase2_gpu_coverage = None;
            let phase2_gpu_admission = match phase2_gpu_workload {
                Phase2GpuAdmissionWorkload::Empty => {
                    phase2_gpu_empty_complete = chunks.is_empty();
                    None
                }
                Phase2GpuAdmissionWorkload::Full { chunks: gpu_chunks } => {
                    match self.phase2_gpu_dfa_catalog(Some(backend.id())) {
                        Some(catalog) => {
                            phase2_gpu_coverage = Some(catalog.coverage());
                            match scan_phase2_gpu_chunks_sharded(catalog, &**backend, gpu_chunks) {
                                Ok(admission) => Some(admission),
                                Err(error) => {
                                    let reason =
                                        format!("phase-2 GPU admission dispatch failed: {error}");
                                    return dispatch_failure(reason);
                                }
                            }
                        }
                        None => None,
                    }
                }
                Phase2GpuAdmissionWorkload::Subset {
                    indices,
                    chunks: gpu_chunks,
                    full_len,
                } => match self.phase2_gpu_dfa_catalog(Some(backend.id())) {
                    Some(catalog) => {
                        phase2_gpu_coverage = Some(catalog.coverage());
                        match scan_phase2_gpu_refs_sharded(
                            catalog,
                            &**backend,
                            gpu_chunks.as_slice(),
                        ) {
                            Ok(admission) => {
                                let admission =
                                    expand_phase2_gpu_admission(admission, &indices, full_len);
                                Some(admission)
                            }
                            Err(error) => {
                                let reason =
                                    format!("phase-2 GPU admission dispatch failed: {error}");
                                return dispatch_failure(reason);
                            }
                        }
                    }
                    None => None,
                },
            };
            let phase2_gpu_s = t_phase2_gpu.elapsed();
            drop(phase2_dispatch_profile);

            let trigger_bits: usize = triggers
                .iter()
                .filter_map(|t| t.as_ref())
                .map(|w| w.iter().map(|x| x.count_ones() as usize).sum::<usize>())
                .sum();

            let t_p2 = std::time::Instant::now();
            let phase2_gpu_admitted = phase2_gpu_admission.as_ref().map_or(0usize, |admission| {
                admission.admitted.iter().filter(|&&v| v).count()
            });
            let phase2_gpu_matches = phase2_gpu_admission
                .as_ref()
                .map_or(0usize, |admission| admission.matches_seen);
            let phase2_gpu_complete = phase2_gpu_empty_complete
                || phase2_gpu_admission
                    .as_ref()
                    .is_some_and(|admission| admission.complete.iter().all(|&value| value));
            let phase2_gpu_complete_rows =
                phase2_gpu_admission.as_ref().map_or(0usize, |admission| {
                    admission.complete.iter().filter(|&&value| value).count()
                });
            let results = self.scan_coalesced_phase2_with_admission(
                chunks,
                triggers,
                phase2_gpu_admission
                    .as_ref()
                    .map(|admission| admission.admitted.as_slice()),
                phase2_gpu_admission
                    .as_ref()
                    .map(|admission| admission.complete.as_slice()),
                Some(phase2_keyword_hints.as_slice()),
                Some(phase2_always_anchor_presence.as_slice()),
                confirmed_anchor_literal_matches.as_deref(),
                generic_keyword_positions.as_deref(),
                execution_route,
            );
            if kh {
                let phase2_always_anchor_chunks = phase2_always_anchor_presence
                    .iter()
                    .filter(|&&present| present)
                    .count();
                let confirmed_anchor_candidate_rows = confirmed_anchor_literal_matches
                    .as_ref()
                    .map_or(0usize, |rows| {
                        rows.iter().filter(|row| !row.is_empty()).count()
                    });
                let confirmed_anchor_candidate_count = confirmed_anchor_literal_matches
                    .as_ref()
                    .map_or(0usize, |rows| rows.iter().map(Vec::len).sum());
                let confirmed_anchor_gpu_complete = confirmed_anchor_literal_matches.is_some();
                let generic_keyword_candidate_rows =
                    generic_keyword_positions.as_ref().map_or(0usize, |rows| {
                        rows.iter().filter(|row| !row.is_empty()).count()
                    });
                let generic_keyword_candidate_count = generic_keyword_positions
                    .as_ref()
                    .map_or(0usize, |rows| rows.iter().map(Vec::len).sum());
                let generic_keyword_gpu_complete = generic_keyword_positions.is_some();
                eprintln!(
                    "perf-trace {}: chunks={} source_bytes={} coalesced_bytes={} max_dispatch_bytes={} dispatches={} batch_mode={} matcher={:.3}s coalesce={:.6}s coalesce_mib_s={:.3} dispatch={:.3}s derive={:.6}s floor={:.3}s phase2_gpu={:.3}s phase2={:.3}s gpu_presence_bits={} underfire_recovered={} trigger_bits={} phase2_gpu_admitted={} phase2_gpu_matches={} phase2_gpu_complete={} phase2_gpu_complete_rows={} phase2_gpu_excluded_oversized={} phase2_gpu_excluded_non_ascii={} phase2_gpu_ascii_patterns={} phase2_gpu_uncovered_ascii_patterns={} phase2_gpu_excluded_redundant_patterns={} phase2_gpu_shards={} phase2_always_anchor_chunks={} confirmed_anchor_gpu_complete={} confirmed_anchor_candidate_rows={} confirmed_anchor_candidates={} generic_keyword_gpu_complete={} generic_keyword_candidate_rows={} generic_keyword_candidates={} full_recall_floor={}",
                    route.label(),
                    chunks.len(),
                    region_source_bytes,
                    region_coalesced_bytes,
                    region_max_dispatch_bytes,
                    region_dispatches,
                    region_batch_mode.label(),
                    matcher_s.as_secs_f64(),
                    co_s.as_secs_f64(),
                    mib_per_second(region_source_bytes, co_s),
                    dis_s.as_secs_f64(),
                    derive_s_total.as_secs_f64(),
                    floor_s.as_secs_f64(),
                    phase2_gpu_s.as_secs_f64(),
                    t_p2.elapsed().as_secs_f64(),
                    gpu_presence_bits,
                    gpu_underfire_recovered,
                    trigger_bits,
                    phase2_gpu_admitted,
                    phase2_gpu_matches,
                    phase2_gpu_complete,
                    phase2_gpu_complete_rows,
                    phase2_gpu_excluded_oversized,
                    phase2_gpu_excluded_non_ascii,
                    phase2_gpu_coverage.map_or(0, |coverage| coverage.covered_ascii_patterns),
                    phase2_gpu_coverage.map_or(0, |coverage| coverage.uncovered_ascii_patterns),
                    phase2_gpu_coverage
                        .map_or(0, |coverage| coverage.excluded_ascii_redundant_patterns),
                    phase2_gpu_coverage.map_or(0, |coverage| coverage.shards),
                    phase2_always_anchor_chunks,
                    confirmed_anchor_gpu_complete,
                    confirmed_anchor_candidate_rows,
                    confirmed_anchor_candidate_count,
                    generic_keyword_gpu_complete,
                    generic_keyword_candidate_rows,
                    generic_keyword_candidate_count,
                    full_recall_floor,
                );
            }
            Ok(results)
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/engine_gpu_region_dispatch.rs"]
mod tests;
