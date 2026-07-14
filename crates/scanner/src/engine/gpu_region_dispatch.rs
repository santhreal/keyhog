//! Live wiring of the coalesced GPU literal-region trigger path.
//!
//! Trigger production is the ONLY thing this path changes. It builds the rule
//! matcher from `ac_map` once, dispatches the chunk batch in the fewest bounded
//! GPU launches, and turns the resulting per-region presence rows into the SAME
//! per-chunk `Option<Vec<u64>>` trigger bitmap the Hyperscan prefilter produces
//! - then hands it to the SHARED `scan_coalesced_phase2`. So windowing,
//! confirmed extraction, fallback, generic, entropy, ML, suppression, dedup,
//! cross-file reassembly and cross-chunk boundary scan are byte-for-byte the
//! coalesced CPU path: the GPU only replaces phase 1.
//!
//! Recall + precision: GPU presence only admits candidate detector bits. Phase 2
//! still validates every candidate with the real detector regex. The full CPU
//! Hyperscan trigger floor is not part of the default fast path; it is enabled
//! only for explicit parity/debug runs.

use super::gpu_region_batch::{
    for_each_region_presence_batch, for_each_region_presence_window,
    region_presence_batch_byte_limit, region_presence_batch_len, region_presence_ref_batch_len,
    region_presence_ref_shards, region_presence_shards, set_trigger_bit, trigger_bit_is_set,
    validate_detector_match, RegionPresenceBatchMode,
};
use super::gpu_region_dispatch_helpers::mib_per_second;
#[cfg(test)]
use super::phase2_gpu_dfa::build_phase2_gpu_admission_workload;
use super::phase2_gpu_dfa::Phase2GpuDfaAdmission;
use super::phase2_gpu_dfa::{
    build_phase2_gpu_admission_workload_filtered, expand_phase2_gpu_admission,
    validate_phase2_gpu_trigger_rows, Phase2GpuAdmissionWorkload,
};
use super::*;

pub(super) fn append_phase2_gpu_admission(
    merged: &mut Phase2GpuDfaAdmission,
    mut shard: Phase2GpuDfaAdmission,
    expected_rows: usize,
) -> std::result::Result<(), String> {
    if shard.admitted.len() != expected_rows || shard.marked.len() != expected_rows {
        return Err(format!(
            "phase-2 GPU admission shard returned admitted={} and marked={} row(s), need {expected_rows}",
            shard.admitted.len(),
            shard.marked.len()
        ));
    }
    merged
        .admitted
        .try_reserve(shard.admitted.len())
        .map_err(|error| format!("phase-2 GPU admitted-row merge reserve failed: {error}"))?;
    merged
        .marked
        .try_reserve(shard.marked.len())
        .map_err(|error| format!("phase-2 GPU marked-row merge reserve failed: {error}"))?;
    merged.admitted.append(&mut shard.admitted);
    merged.marked.append(&mut shard.marked);
    merged.complete &= shard.complete;
    merged.matches_seen = merged
        .matches_seen
        .checked_add(shard.matches_seen)
        .ok_or_else(|| "phase-2 GPU match count overflow across shards".to_string())?;
    Ok(())
}

fn scan_phase2_gpu_chunks_sharded(
    catalog: &super::phase2_gpu_dfa::Phase2GpuDfaCatalog,
    backend: &dyn vyre::VyreBackend,
    chunks: &[keyhog_core::Chunk],
) -> std::result::Result<Phase2GpuDfaAdmission, String> {
    let byte_limit = region_presence_batch_byte_limit(backend.id());
    if region_presence_batch_len(chunks)? <= byte_limit {
        return catalog.scan_admission_chunks(backend, chunks);
    }
    let shards = region_presence_shards(chunks, byte_limit)?;
    let mut merged = Phase2GpuDfaAdmission {
        admitted: Vec::new(),
        complete: true,
        matches_seen: 0,
        marked: Vec::new(),
    };
    merged
        .admitted
        .try_reserve(chunks.len())
        .map_err(|error| format!("phase-2 GPU admitted-row reserve failed: {error}"))?;
    merged
        .marked
        .try_reserve(chunks.len())
        .map_err(|error| format!("phase-2 GPU marked-row reserve failed: {error}"))?;
    for shard in shards {
        let shard = shard?;
        let rows = shard.chunks.len();
        let admission = catalog.scan_admission_chunks(backend, &chunks[shard.chunks])?;
        append_phase2_gpu_admission(&mut merged, admission, rows)?;
    }
    Ok(merged)
}

fn scan_phase2_gpu_refs_sharded(
    catalog: &super::phase2_gpu_dfa::Phase2GpuDfaCatalog,
    backend: &dyn vyre::VyreBackend,
    chunks: &[&keyhog_core::Chunk],
) -> std::result::Result<Phase2GpuDfaAdmission, String> {
    let byte_limit = region_presence_batch_byte_limit(backend.id());
    if region_presence_ref_batch_len(chunks)? <= byte_limit {
        return catalog.scan_admission_refs(backend, chunks);
    }
    let shards = region_presence_ref_shards(chunks, byte_limit)?;
    let mut merged = Phase2GpuDfaAdmission {
        admitted: Vec::new(),
        complete: true,
        matches_seen: 0,
        marked: Vec::new(),
    };
    merged
        .admitted
        .try_reserve(chunks.len())
        .map_err(|error| format!("phase-2 GPU admitted-row reserve failed: {error}"))?;
    merged
        .marked
        .try_reserve(chunks.len())
        .map_err(|error| format!("phase-2 GPU marked-row reserve failed: {error}"))?;
    for shard in shards {
        let shard = shard?;
        let rows = shard.chunks.len();
        let admission = catalog.scan_admission_refs(backend, &chunks[shard.chunks])?;
        append_phase2_gpu_admission(&mut merged, admission, rows)?;
    }
    Ok(merged)
}

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
    /// other backend uses. If the matcher/backend is unavailable or dispatch
    /// fails, the selected GPU route terminates with exit `12`; it never
    /// substitutes an unselected CPU/SIMD path.
    pub(crate) fn scan_coalesced_gpu_region_presence(
        &self,
        chunks: &[keyhog_core::Chunk],
        backend: crate::hw_probe::ScanBackend,
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        match self.try_scan_coalesced_gpu_region_presence(chunks, backend) {
            Ok(results) => results,
            Err(error) => super::gpu_forced::fail_selected_gpu_dispatch_error(self, error),
        }
    }

    /// Result-returning production GPU path for health diagnostics. Normal scan
    /// entry points use `scan_coalesced_gpu_region_presence`, which maps this
    /// structured failure to the public exit-12 contract. The backend self-test
    /// consumes the error in-band so it can emit its complete JSON report and
    /// documented health-check exit code.
    pub(crate) fn try_scan_coalesced_gpu_region_presence(
        &self,
        chunks: &[keyhog_core::Chunk],
        route: crate::hw_probe::ScanBackend,
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
            let Some(resident_slot) = self.gpu_resident_presence_slot(route) else {
                return dispatch_failure(format!(
                    "{} has no scanner-owned resident pipeline slot",
                    route.label()
                ));
            };

            let words = self.ac_map.len().div_ceil(64).max(1);
            let gpu_literal_count = self.gpu_presence_literal_count();
            let presence_words = gpu_literal_count.div_ceil(32).max(1);
            let region_source_bytes = chunks.iter().try_fold(0usize, |total, chunk| {
                total.checked_add(chunk.data.len()).ok_or_else(|| {
                    super::gpu_forced::SelectedGpuDispatchError::new(
                        "GPU region-presence source-byte accounting overflows host usize"
                            .to_string(),
                    )
                })
            })?;
            let expected_presence_words =
                chunks.len().checked_mul(presence_words).ok_or_else(|| {
                    super::gpu_forced::SelectedGpuDispatchError::new(
                        "region-presence readback size overflows host usize".to_string(),
                    )
                })?;

            let t_co = std::time::Instant::now();
            let mut dis_s = std::time::Duration::ZERO;
            let mut derive_s_total = std::time::Duration::ZERO;
            let region_dispatch_profile = super::profile::span(super::profile::P::BackendDispatch);
            let mut logical_presence = Vec::new();
            logical_presence
                .try_reserve_exact(expected_presence_words)
                .map_err(|error| {
                    super::gpu_forced::SelectedGpuDispatchError::new(format!(
                        "GPU region-presence logical-row reserve failed: {error}"
                    ))
                })?;
            logical_presence.resize(expected_presence_words, 0u32);
            let mut logical_rows_seen = Vec::new();
            logical_rows_seen
                .try_reserve_exact(chunks.len())
                .map_err(|error| {
                    super::gpu_forced::SelectedGpuDispatchError::new(format!(
                        "GPU region-presence row-state reserve failed: {error}"
                    ))
                })?;
            logical_rows_seen.resize(chunks.len(), false);
            let mut triggers: Vec<Option<Vec<u64>>> = Vec::new();
            let mut phase2_keyword_hints: Vec<Vec<u32>> = Vec::new();
            let mut phase2_always_anchor_presence: Vec<bool> = Vec::new();
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
            let mut dispatch_presence = |haystack: &[u8],
                                         region_starts: &[u32],
                                         logical_start: usize,
                                         rows: usize| {
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
                    super::gpu_resident_presence::scan_gpu_literal_presence_by_region_resident(
                        resident_slot,
                        matcher,
                        backend,
                        haystack,
                        region_starts,
                        |presence| {
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
                                let start =
                                    row_idx.checked_mul(presence_words).ok_or_else(|| {
                                        "region-presence logical row offset overflows host usize"
                                            .to_string()
                                    })?;
                                let end = start.checked_add(presence_words).ok_or_else(|| {
                                    "region-presence logical row end overflows host usize"
                                        .to_string()
                                })?;
                                let target =
                                    logical_presence.get_mut(start..end).ok_or_else(|| {
                                        format!(
                                            "region-presence logical row {row_idx} is out of range"
                                        )
                                    })?;
                                for (target_word, &word) in target.iter_mut().zip(row) {
                                    *target_word |= word;
                                }
                                let seen = logical_rows_seen.get_mut(row_idx).ok_or_else(|| {
                                    format!(
                                        "region-presence logical row state {row_idx} is out of range"
                                    )
                                })?;
                                *seen = true;
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
            let mut region_dispatches = 0usize;
            let mut region_coalesced_bytes = 0usize;
            let mut region_max_dispatch_bytes = 0usize;
            let mut region_batch_mode = RegionPresenceBatchMode::FoldedScratch;
            let mut cursor = 0usize;
            while cursor < chunks.len() {
                let oversized = chunks[cursor].data.len() > byte_limit;
                let (summary, next_cursor) = if oversized {
                    let logical_row = cursor;
                    (
                        for_each_region_presence_window(
                            chunks[cursor].data.as_bytes(),
                            byte_limit,
                            self.gpu_max_literal_len,
                            |haystack, _range| dispatch_presence(haystack, &[0], logical_row, 1),
                        ),
                        cursor + 1,
                    )
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
                                dispatch_presence(
                                    haystack,
                                    region_starts,
                                    run_start + shard.chunks.start,
                                    shard.chunks.len(),
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
            if let Some(missing_row) = logical_rows_seen.iter().position(|&seen| !seen) {
                drop(region_dispatch_profile);
                return dispatch_failure(format!(
                    "GPU region-presence produced no physical window for logical chunk {missing_row}"
                ));
            }
            let t_logical_derive = std::time::Instant::now();
            let mut gpu_presence_bits = 0usize;
            for row in logical_presence.chunks_exact(presence_words) {
                gpu_presence_bits = gpu_presence_bits
                    .checked_add(
                        row.iter()
                            .map(|word| word.count_ones() as usize)
                            .sum::<usize>(),
                    )
                    .ok_or_else(|| {
                        super::gpu_forced::SelectedGpuDispatchError::new(
                            "region-presence reduced bit count overflows host usize",
                        )
                    })?;
                let bits = self.triggered_patterns_from_gpu_presence(row);
                phase2_keyword_hints.push(self.phase2_keyword_hints_from_gpu_presence(row));
                phase2_always_anchor_presence
                    .push(self.phase2_always_anchor_present_from_gpu_presence(row));
                triggers.push(bits.iter().any(|&word| word != 0).then_some(bits));
            }
            derive_s_total += t_logical_derive.elapsed();
            let co_s = t_co
                .elapsed()
                .saturating_sub(dis_s)
                .saturating_sub(derive_s_total);
            drop(region_dispatch_profile);
            let confirmed_anchor_literal_matches: Option<Vec<Vec<(u32, u32)>>> = None;
            let generic_keyword_positions: Option<Vec<Vec<u32>>> = None;

            let t_floor = std::time::Instant::now();
            let full_recall_floor = self.tuning.gpu_recall_floor_enabled();
            let cpu_triggers = if full_recall_floor {
                match self.simd_prefilter.as_ref() {
                    Some(scanner) => Some(self.compute_coalesced_triggers(chunks, scanner)),
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
            let mut phase2_gpu_excluded_oversized = false;
            for (idx, chunk) in chunks.iter().enumerate() {
                let row_has_trigger = triggers
                    .get(idx)
                    .and_then(|trigger| trigger.as_ref())
                    .is_some_and(|bits| bits.iter().any(|&word| word != 0));
                if row_has_trigger {
                    phase2_gpu_row_needed.push(true);
                    continue;
                }
                if chunk.data.len() > phase2_gpu_byte_limit {
                    phase2_gpu_excluded_oversized = true;
                    phase2_gpu_row_needed.push(false);
                    continue;
                }
                // Encoded-only rows that CPU admission would route straight to
                // decode-only recovery do not need the prefixless phase-2 GPU
                // DFA. The shared phase-2 tail still runs decode-only on those
                // rows; this just avoids a redundant GPU admission dispatch.
                let decode_only_row = self.chunk_needs_decode_postprocess(chunk)
                    && !self.should_scan_no_hit_chunk(chunk);
                phase2_gpu_row_needed.push(!decode_only_row);
            }
            let phase2_gpu_workload =
                build_phase2_gpu_admission_workload_filtered(chunks, &triggers, |idx, _| {
                    phase2_gpu_row_needed[idx]
                });
            let phase2_dispatch_profile = super::profile::span(super::profile::P::BackendDispatch);
            let t_phase2_gpu = std::time::Instant::now();
            let mut phase2_gpu_empty_complete = false;
            let phase2_gpu_admission = match phase2_gpu_workload {
                Phase2GpuAdmissionWorkload::Empty => {
                    phase2_gpu_empty_complete = !phase2_gpu_excluded_oversized;
                    None
                }
                Phase2GpuAdmissionWorkload::Full { chunks: gpu_chunks } => {
                    match self.phase2_gpu_dfa_catalog(Some(backend.id())) {
                        Some(catalog) => {
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
                        match scan_phase2_gpu_refs_sharded(
                            catalog,
                            &**backend,
                            gpu_chunks.as_slice(),
                        ) {
                            Ok(admission) => {
                                let mut admission =
                                    expand_phase2_gpu_admission(admission, &indices, full_len);
                                admission.complete &= !phase2_gpu_excluded_oversized;
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
                    .is_some_and(|admission| admission.complete);
            let results = self.scan_coalesced_phase2_with_admission(
                chunks,
                triggers,
                phase2_gpu_admission
                    .as_ref()
                    .map(|admission| admission.admitted.as_slice()),
                Some(phase2_keyword_hints.as_slice()),
                Some(phase2_always_anchor_presence.as_slice()),
                confirmed_anchor_literal_matches.as_deref(),
                generic_keyword_positions.as_deref(),
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
                    "perf-trace {}: chunks={} source_bytes={} coalesced_bytes={} max_dispatch_bytes={} dispatches={} batch_mode={} matcher={:.3}s coalesce={:.6}s coalesce_mib_s={:.3} dispatch={:.3}s derive={:.6}s floor={:.3}s phase2_gpu={:.3}s phase2={:.3}s gpu_presence_bits={} underfire_recovered={} trigger_bits={} phase2_gpu_admitted={} phase2_gpu_matches={} phase2_gpu_complete={} phase2_always_anchor_chunks={} confirmed_anchor_gpu_complete={} confirmed_anchor_candidate_rows={} confirmed_anchor_candidates={} generic_keyword_gpu_complete={} generic_keyword_candidate_rows={} generic_keyword_candidates={} full_recall_floor={}",
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
