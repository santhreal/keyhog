//! Live wiring of the coalesced GPU literal-region trigger path.
//!
//! Trigger production is the ONLY thing this path changes. It builds the rule
//! matcher from `ac_map` once, dispatches the whole chunk batch in ONE GPU
//! launch, and turns the resulting per-region presence rows into the SAME
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
    set_trigger_bit, trigger_bit_is_set, validate_detector_match, with_region_presence_batch,
    RegionPresenceBatchMode,
};
use super::gpu_region_dispatch_helpers::mib_per_second;
#[cfg(test)]
use super::phase2_gpu_dfa::build_phase2_gpu_admission_workload;
#[cfg(test)]
use super::phase2_gpu_dfa::Phase2GpuDfaAdmission;
use super::phase2_gpu_dfa::{
    build_phase2_gpu_admission_workload_filtered, expand_phase2_gpu_admission,
    validate_phase2_gpu_trigger_rows, Phase2GpuAdmissionWorkload,
};
use super::*;
struct GpuRegionPresenceEvidence {
    presence: Vec<u32>,
    confirmed_anchor_literal_matches: Option<Vec<Vec<(u32, u32)>>>,
    generic_keyword_positions: Option<Vec<Vec<u32>>>,
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

    /// Coalesced GPU region-presence scan: one GPU dispatch over the whole
    /// `chunks` batch produces the per-chunk trigger bitmap, then the SHARED
    /// coalesced phase-2 tail runs the identical per-chunk extraction every
    /// other backend uses. If the matcher/backend is unavailable or dispatch
    /// fails, the selected GPU route terminates with exit `12`; it never
    /// substitutes an unselected CPU/SIMD path.
    pub(crate) fn scan_coalesced_gpu_region_presence(
        &self,
        chunks: &[keyhog_core::Chunk],
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        match self.try_scan_coalesced_gpu_region_presence(chunks) {
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
            let Some(backend) = self.gpu_backend.as_ref() else {
                return dispatch_failure(
                    "no gpu backend acquired for coalesced region dispatch".to_string(),
                );
            };

            let words = self.ac_map.len().div_ceil(64).max(1);
            let gpu_literal_count = self.gpu_presence_literal_count();
            let presence_words = gpu_literal_count.div_ceil(32).max(1);
            let region_source_bytes: usize = chunks.iter().map(|chunk| chunk.data.len()).sum();

            let t_co = std::time::Instant::now();
            let mut co_s = std::time::Duration::ZERO;
            let mut dis_s = std::time::Duration::ZERO;
            let mut region_coalesced_bytes = 0usize;
            let mut region_batch_mode = RegionPresenceBatchMode::FoldedScratch;
            let region_dispatch_profile = super::profile::span(super::profile::P::BackendDispatch);
            let evidence = match with_region_presence_batch(
                chunks,
                |haystack, region_starts, batch_mode| {
                    co_s = t_co.elapsed();
                    region_coalesced_bytes = haystack.len();
                    region_batch_mode = batch_mode;
                    let t_dis = std::time::Instant::now();
                    let result =
                        super::gpu_literal_scratch::scan_gpu_literal_presence_by_region_with_scratch(
                            matcher,
                            &**backend,
                            haystack,
                            region_starts,
                        )
                        .map_err(|error| format!("region-presence dispatch error: {error}"));
                    dis_s = t_dis.elapsed();
                    let presence = result?;
                    Ok(GpuRegionPresenceEvidence {
                        presence,
                        confirmed_anchor_literal_matches: None,
                        generic_keyword_positions: None,
                    })
                },
            ) {
                Ok(evidence) => evidence,
                Err(error) => {
                    drop(region_dispatch_profile);
                    return dispatch_failure(error);
                }
            };
            drop(region_dispatch_profile);
            let presence = evidence.presence;
            let confirmed_anchor_literal_matches = evidence.confirmed_anchor_literal_matches;
            let generic_keyword_positions = evidence.generic_keyword_positions;

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

            let expected_presence_words = chunks.len().saturating_mul(presence_words);
            if presence.len() != expected_presence_words {
                return dispatch_failure(format!(
                    "region-presence readback length mismatch: got {} u32 word(s), need {}",
                    presence.len(),
                    expected_presence_words
                ));
            }

            let mut triggers: Vec<Option<Vec<u64>>> = Vec::with_capacity(chunks.len());
            let mut phase2_keyword_hints: Vec<Vec<u32>> = Vec::with_capacity(chunks.len());
            let mut phase2_always_anchor_presence: Vec<bool> = Vec::with_capacity(chunks.len());
            let mut gpu_presence_bits = 0usize;
            for (row_idx, row) in presence
                .chunks_exact(presence_words)
                .take(chunks.len())
                .enumerate()
            {
                if let Some((word_idx, stray_bits)) = self.gpu_presence_stray_tail_bits(row) {
                    return dispatch_failure(format!(
                        "region-presence readback row {row_idx} has out-of-range detector bit(s): word {word_idx} bits 0x{stray_bits:08x} beyond {} literal(s)",
                        gpu_literal_count
                    ));
                }
                gpu_presence_bits += row
                    .iter()
                    .map(|word| word.count_ones() as usize)
                    .sum::<usize>();
                let bits = self.triggered_patterns_from_gpu_presence(row);
                phase2_keyword_hints.push(self.phase2_keyword_hints_from_gpu_presence(row));
                phase2_always_anchor_presence
                    .push(self.phase2_always_anchor_present_from_gpu_presence(row));
                if bits.iter().any(|&word| word != 0) {
                    triggers.push(Some(bits));
                } else {
                    triggers.push(None);
                }
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
            for (idx, chunk) in chunks.iter().enumerate() {
                let row_has_trigger = triggers
                    .get(idx)
                    .and_then(|trigger| trigger.as_ref())
                    .is_some_and(|bits| bits.iter().any(|&word| word != 0));
                if row_has_trigger {
                    phase2_gpu_row_needed.push(true);
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
                    phase2_gpu_empty_complete = true;
                    None
                }
                Phase2GpuAdmissionWorkload::Full { chunks: gpu_chunks } => {
                    match self.phase2_gpu_dfa_catalog(Some(backend.id())) {
                        Some(catalog) => {
                            match catalog.scan_admission_chunks(&**backend, gpu_chunks) {
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
                        match catalog.scan_admission_refs(&**backend, gpu_chunks.as_slice()) {
                            Ok(admission) => {
                                Some(expand_phase2_gpu_admission(admission, &indices, full_len))
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
                    "perf-trace gpu-region-presence: chunks={} source_bytes={} coalesced_bytes={} batch_mode={} matcher={:.3}s coalesce={:.6}s coalesce_mib_s={:.3} dispatch={:.3}s floor={:.3}s phase2_gpu={:.3}s phase2={:.3}s gpu_presence_bits={} underfire_recovered={} trigger_bits={} phase2_gpu_admitted={} phase2_gpu_matches={} phase2_gpu_complete={} phase2_always_anchor_chunks={} confirmed_anchor_gpu_complete={} confirmed_anchor_candidate_rows={} confirmed_anchor_candidates={} generic_keyword_gpu_complete={} generic_keyword_candidate_rows={} generic_keyword_candidates={} full_recall_floor={}",
                    chunks.len(),
                    region_source_bytes,
                    region_coalesced_bytes,
                    region_batch_mode.label(),
                    matcher_s.as_secs_f64(),
                    co_s.as_secs_f64(),
                    mib_per_second(region_source_bytes, co_s),
                    dis_s.as_secs_f64(),
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
